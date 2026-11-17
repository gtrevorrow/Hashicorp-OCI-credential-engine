#!/usr/bin/env python3
"""Private, checkout-scoped lifecycle and smoke checks for disposable Vault only."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / '.vault-dev'
ADDR = 'http://127.0.0.1:8200'


class SafeError(Exception):
    """A message safe to display without subprocess output or credentials."""


def private_path(path, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise SafeError('Refusing unsafe permissions, ownership, or symlink in dev state.')


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(text)


def cli_env(token=''):
    # Do not inherit alternate Vault routing, namespaces, token helpers, or proxies.
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('VAULT_', 'OCI_')) and not k.lower().endswith('_proxy')}
    env.update(VAULT_ADDR=ADDR, VAULT_TOKEN=token, VAULT_MAX_RETRIES='0')
    return env


def command(args, *, data=None, env=None, timeout=60):
    result = subprocess.run(args, input=data, text=True, capture_output=True,
                            env=env or cli_env(), timeout=timeout)
    if result.returncode:
        # Vault errors can repeat response bodies, JWTs, and submitted secrets.
        raise SafeError('Command failed; credential-bearing output was suppressed.')
    return result.stdout


def vault(token, *args, payload=None):
    if payload is not None:
        args = (*args, '-')
    output = command(['vault', *args], env=cli_env(token),
                     data=json.dumps(payload) if payload is not None else None,
                     timeout=5 if args[0] == 'status' else 60)
    return json.loads(output) if '-format=json' in args and output.strip() else {}


def process_identity(pid):
    return command(['ps', '-p', str(pid), '-o', 'lstart=', '-o', 'command=']).strip()


def load_session():
    private_path(STATE / 'session.json')
    session = json.loads((STATE / 'session.json').read_text())
    name = session['run']
    if not isinstance(name, str) or not name.startswith('run-') or Path(name).name != name:
        raise SafeError('Invalid dev session directory.')
    run = STATE / name
    private_path(run, directory=True)
    private_path(run / 'token')
    return session, run, (run / 'token').read_text()


def verify_process(session):
    pid = session['pid']
    if not isinstance(pid, int) or pid <= 1:
        raise SafeError('Invalid managed Vault PID.')
    if process_identity(pid) != session['process']:
        raise SafeError('Managed Vault process no longer matches; refusing to act on a reused PID.')


def verify_target(session, token):
    verify_process(session)
    status = vault(token, 'status', '-format=json')
    if not session.get('cluster') or status.get('cluster_id') != session['cluster']:
        raise SafeError('Vault cluster does not match this checkout’s dev session.')
    lookup = vault(token, 'token', 'lookup', '-format=json')
    if 'root' not in lookup.get('data', {}).get('policies', []):
        raise SafeError('Managed dev token did not authenticate as the expected root token.')


def load_config():
    source = ROOT / '.env.local'
    if not source.exists():
        return {}
    # This remains a trusted shell file, as in the original helper. Capture output.
    private_path(source)
    output = command(['bash', '-c', 'set +x; set -ae; source "$1" >/dev/null; env -0',
                      'dev-settings', str(source)])
    values = dict(item.split('=', 1) for item in output.split('\0') if '=' in item)
    config = {k[4:].lower(): v for k, v in values.items() if k.startswith('OCI_') and v}
    for key in list(config):
        if key.endswith('_enabled') or key in ('enable_plugin_issued_subject_token', 'strict_role_name_match',
                                               'debug_return_resolved_subject_token_claims', 'debug_allow_brokered_http'):
            if config[key] not in ('true', 'false'):
                raise SafeError('Boolean OCI settings must be true or false.')
            config[key] = config[key] == 'true'
    if config.get('subject_token_self_mint_enabled') or config.get('brokered_subject_token_enabled'):
        if not config.get('subject_token_self_mint_private_key'):
            key = ROOT / '.vault-dev-self-mint-key.pem'
            if not key.exists():
                write_private(key, command(['openssl', 'genrsa', '2048']))
            private_path(key)
            config['subject_token_self_mint_private_key'] = key.read_text()
    return config


def start():
    if (STATE / 'session.json').exists():
        raise SafeError('A dev session already exists. Use stop before starting another.')
    # Refuse an occupied port before starting; the random root token also prevents
    # a different server from passing readiness or receiving configuration writes.
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 8200))
    config = load_config()
    command(['make', '-C', str(ROOT), 'build'], timeout=300)
    run = Path(tempfile.mkdtemp(prefix='run-', dir=STATE))
    plugins = run / 'plugins'
    plugins.mkdir(mode=0o700)
    binary = plugins / 'vault-plugin-secrets-oci'
    shutil.copy2(ROOT / 'bin' / binary.name, binary)
    token = secrets.token_urlsafe(32)
    write_private(run / 'token', token)
    env = cli_env()
    env['VAULT_DEV_ROOT_TOKEN_ID'] = token
    proc = None
    try:
        with (run / 'vault.log').open('x') as log:
            proc = subprocess.Popen(['vault', 'server', '-dev', '-dev-no-store-token',
                                     '-dev-listen-address=127.0.0.1:8200',
                                     '-dev-plugin-dir=' + str(plugins)],
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                    env=env, start_new_session=True)
        status = None
        for _ in range(30):
            if proc.poll() is not None:
                raise SafeError('Dev Vault exited before readiness; inspect its private log locally.')
            try:
                status = vault(token, 'status', '-format=json')
                vault(token, 'token', 'lookup', '-format=json')
                break
            except SafeError:
                time.sleep(1)
        if proc.poll() is not None or not status or not status.get('cluster_id'):
            raise SafeError('Dev Vault did not become ready.')
        session = {'run': run.name, 'pid': proc.pid, 'process': process_identity(proc.pid),
                   'cluster': status['cluster_id']}
        verify_target(session, token)
        write_private(STATE / 'session.json', json.dumps(session))
        vault(token, 'write', '-format=json', 'sys/plugins/catalog/secret/oci', payload={
            'sha_256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'command': binary.name})
        vault(token, 'secrets', 'enable', '-path=oci', '-plugin-name=oci', 'plugin')
        if all(config.get(k) for k in ('domain_url', 'client_id', 'client_secret')):
            vault(token, 'write', '-format=json', 'oci/config', payload=config)
        else:
            print('OCI config not seeded; configure .env.local before running the smoke test.')
    except BaseException:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=10)
        (STATE / 'session.json').unlink(missing_ok=True)
        # Retain the private log for diagnosis, but discard the unusable root token.
        (run / 'token').unlink(missing_ok=True)
        raise
    print('Dev Vault is ready at ' + ADDR + '. Private log: ' + str(run / 'vault.log'))
    print('Load CLI settings with: eval "$(./scripts/dev_vault.sh env)"')


def stop():
    session, run, _ = load_session()
    verify_process(session)
    os.kill(session['pid'], signal.SIGTERM)
    for _ in range(50):
        try:
            if process_identity(session['pid']) != session['process']:
                break
        except SafeError:
            break
        time.sleep(0.1)
    else:
        raise SafeError('Managed Vault has not stopped; retained state for a later stop attempt.')
    shutil.rmtree(run)
    (STATE / 'session.json').unlink()
    print('Managed dev Vault stopped; session credentials and log removed.')


def exports():
    session, run, token = load_session()
    verify_target(session, token)
    print('unset VAULT_AGENT_ADDR VAULT_NAMESPACE VAULT_PROXY_ADDR VAULT_TLS_SERVER_NAME VAULT_SKIP_VERIFY '
          'HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy')
    print('export VAULT_ADDR=' + shlex.quote(ADDR))
    # The generated shell text references the private file, never the token value.
    print('export VAULT_TOKEN="$(cat ' + shlex.quote(str(run / 'token')) + ')"')


def smoke():
    session, _, root_token = load_session()
    verify_target(session, root_token)
    original = vault(root_token, 'read', '-format=json', 'oci/config')['data']
    name = 'oci-smoke-' + secrets.token_hex(8)
    password = secrets.token_urlsafe(32)
    cleanup = []
    failed_cleanup = False
    try:
        # Every resource belongs to this invocation; never overwrite userpass/ or developer.
        cleanup.append(('auth', 'disable', name))
        vault(root_token, 'auth', 'enable', '-path=' + name, 'userpass')
        accessor = vault(root_token, 'auth', 'list', '-format=json')[name + '/']['accessor']
        cleanup.append(('write', '-format=json', 'oci/config', {
            'subject_token_identity_alias_mount_accessor': original.get('subject_token_identity_alias_mount_accessor', ''),
            'debug_return_resolved_subject_token_claims': original.get('debug_return_resolved_subject_token_claims', False)}))
        vault(root_token, 'write', '-format=json', 'oci/config', payload={
            'subject_token_identity_alias_mount_accessor': accessor, 'debug_return_resolved_subject_token_claims': True})
        policy = 'path "oci/exchange/' + name + '" { capabilities = ["create", "update"] }'
        cleanup.append(('delete', 'sys/policies/acl/' + name))
        vault(root_token, 'write', '-format=json', 'sys/policies/acl/' + name, payload={'policy': policy})
        group = vault(root_token, 'write', '-format=json', 'identity/group', payload={'name': name, 'type': 'internal'})['data']['id']
        cleanup.append(('delete', 'identity/group/id/' + group))
        vault(root_token, 'write', '-format=json', 'auth/' + name + '/users/test',
              payload={'password': password, 'token_policies': name, 'token_ttl': '5m', 'token_max_ttl': '5m'})
        claims = {'entity_ref': '{{ vault.entity.id }}', 'entity_name': '{{ vault.entity.name }}',
                  'mount_type': '{{ vault.request.mount_type }}', 'group_list': '{{ join(vault.groups, ",") }}'}
        cleanup.append(('delete', 'oci/role/' + name))
        vault(root_token, 'write', '-format=json', 'oci/role/' + name,
              payload={'self_mint_custom_claims': json.dumps(claims)})
        login = vault('', 'write', '-format=json', 'auth/' + name + '/login/test', payload={'password': password})['auth']
        entity = login['entity_id']
        cleanup.append(('delete', 'identity/entity/id/' + entity))
        cleanup.append(('write', '-format=json', 'auth/token/revoke-accessor', {'accessor': login['accessor']}))
        vault(root_token, 'write', '-format=json', 'identity/group/id/' + group,
              payload={'member_entity_ids': [entity]})
        login = vault('', 'write', '-format=json', 'auth/' + name + '/login/test', payload={'password': password})['auth']
        cleanup.append(('write', '-format=json', 'auth/token/revoke-accessor', {'accessor': login['accessor']}))
        response = vault(login['client_token'], 'write', '-format=json', 'oci/exchange/' + name, payload={
            'requested_token_type': os.environ.get('SMOKE_REQUESTED_TOKEN_TYPE', 'urn:oci:token-type:oci-rpst'),
            'res_type': os.environ.get('SMOKE_RES_TYPE', 'ref_vault')})['data']
        resolved = response.get('resolved_subject_token_claims', {})
        if not (any(response.get(k) for k in ('rpst_token', 'session_token', 'access_token'))
                and resolved.get('entity_ref') == entity and resolved.get('entity_name')
                and resolved.get('mount_type') == 'oci' and resolved.get('vault_alias_mount_accessor') == accessor
                and resolved.get('vault_alias_mount_type') == 'userpass'
                and name in resolved.get('group_list', '').split(',')):
            raise SafeError('Smoke claim or credential assertions failed; response suppressed.')
    finally:
        # Recheck identity before cleanup too; never clean up on a replacement server.
        verify_target(session, root_token)
        for action in reversed(cleanup):
            try:
                if isinstance(action[-1], dict):
                    vault(root_token, *action[:-1], payload=action[-1])
                else:
                    vault(root_token, *action)
            except (SafeError, OSError, ValueError, subprocess.TimeoutExpired):
                failed_cleanup = True
        if failed_cleanup:
            raise SafeError('Smoke cleanup incomplete for ' + name + '; stop the disposable dev server.')
    print('Smoke passed: credential received and identity claims verified. Test resources removed; no credentials printed.')


def interrupt(_signum, _frame):
    raise KeyboardInterrupt


def main():
    signal.signal(signal.SIGTERM, interrupt)
    os.umask(0o077)
    if os.environ.get('VAULT_ADDR', ADDR) != ADDR:
        raise SafeError('These helpers only target the managed dev Vault at ' + ADDR + '; unset VAULT_ADDR first.')
    STATE.mkdir(mode=0o700, exist_ok=True)
    private_path(STATE, directory=True)
    lock = STATE / 'lock'
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        private_path(lock)
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SafeError('Another dev helper is running in this checkout.')
        actions = {'start': start, 'stop': stop, 'env': exports, 'smoke': smoke}
        if len(sys.argv) != 2 or sys.argv[1] not in actions:
            raise SafeError('Usage: dev_vault.sh {start|stop|env} or smoke_self_mint_non_root.sh')
        actions[sys.argv[1]]()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Dev helper interrupted; cleanup was attempted. Stop the managed server if cleanup was interrupted.', file=sys.stderr)
        sys.exit(130)
    except SafeError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        print('Dev helper failed. Check prerequisites and private dev state; raw error output suppressed.', file=sys.stderr)
        sys.exit(1)
