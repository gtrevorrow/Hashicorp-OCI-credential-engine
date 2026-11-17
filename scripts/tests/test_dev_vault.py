"""Exercise security boundaries without a real Vault or OCI tenancy."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('dev_vault', Path(__file__).parents[1] / 'dev_vault.py')
dev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dev)


class HelperTests(unittest.TestCase):
    def test_secret_payload_uses_stdin_and_failure_output_is_suppressed(self):
        with patch.object(dev.subprocess, 'run') as run:
            run.return_value = subprocess.CompletedProcess([], 0, '{}', '')
            dev.vault('root-sentinel', 'write', '-format=json', 'oci/config',
                      payload={'client_secret': 'secret-sentinel', 'key': 'key-sentinel'})
            args, kwargs = run.call_args
            self.assertEqual(args[0], ['vault', 'write', '-format=json', 'oci/config', '-'])
            self.assertIn('secret-sentinel', kwargs['input'])
            self.assertEqual(kwargs['env']['VAULT_TOKEN'], 'root-sentinel')
            run.return_value = subprocess.CompletedProcess([], 1, 'secret-sentinel', 'key-sentinel')
            with self.assertRaises(dev.SafeError) as error:
                dev.vault('root-sentinel', 'write', 'oci/config', payload={'client_secret': 'secret-sentinel'})
            self.assertNotIn('sentinel', str(error.exception))

    def test_inherited_routing_and_credentials_are_removed(self):
        with patch.dict(os.environ, {'VAULT_AGENT_ADDR': 'https://other', 'VAULT_NAMESPACE': 'production',
                                     'VAULT_TOKEN': 'other-token', 'HTTPS_PROXY': 'https://proxy',
                                     'OCI_CLIENT_SECRET': 'other-secret'}):
            env = dev.cli_env('managed')
        self.assertEqual(env['VAULT_ADDR'], dev.ADDR)
        self.assertEqual(env['VAULT_TOKEN'], 'managed')
        for name in ('VAULT_AGENT_ADDR', 'VAULT_NAMESPACE', 'HTTPS_PROXY', 'OCI_CLIENT_SECRET'):
            self.assertNotIn(name, env)

    def test_wrong_address_fails_before_state_or_cli_access(self):
        with patch.dict(os.environ, {'VAULT_ADDR': 'https://production.example'}), patch.object(dev, 'vault') as cli:
            with self.assertRaises(dev.SafeError):
                dev.main()
            cli.assert_not_called()

    def test_private_paths_reject_shared_permissions_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'state'
            dev.write_private(path, 'secret')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            dev.private_path(path)
            link = Path(tmp) / 'link'
            link.symlink_to(path)
            with self.assertRaises(dev.SafeError):
                dev.private_path(link)
            path.chmod(0o644)
            with self.assertRaises(dev.SafeError):
                dev.private_path(path)

    def test_reused_pid_and_wrong_cluster_fail_before_mutation(self):
        session = {'pid': 123, 'process': 'managed', 'cluster': 'ours'}
        with patch.object(dev, 'process_identity', return_value='other'), patch.object(dev, 'vault') as cli:
            with self.assertRaises(dev.SafeError):
                dev.verify_target(session, 'root')
            cli.assert_not_called()
        with patch.object(dev, 'process_identity', return_value='managed'), patch.object(dev, 'vault', return_value={'cluster_id': 'other'}) as cli:
            with self.assertRaises(dev.SafeError):
                dev.verify_target(session, 'root')
            self.assertEqual(cli.call_count, 1)

    def test_exports_reference_private_token_without_printing_it(self):
        with patch.object(dev, 'load_session', return_value=({}, Path('/private/dev run'), 'root-sentinel')), patch.object(dev, 'verify_target'):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                dev.exports()
            self.assertNotIn('root-sentinel', out.getvalue())
            self.assertIn('$(cat', out.getvalue())
            self.assertIn("'/private/dev run/token'", out.getvalue())

    def run_smoke(self, fail_exchange=False, bad_claims=False, cleanup_failure=False):
        calls = []
        issued = []
        original = {'subject_token_identity_alias_mount_accessor': 'previous', 'debug_return_resolved_subject_token_claims': False}
        def cli(token, *args, payload=None):
            calls.append((token, args, payload))
            path = args[-1]
            if args[:2] == ('auth', 'enable'):
                issued.append(args[2][len('-path='):])
            if args[0] == 'read':
                return {'data': original}
            if args[:2] == ('auth', 'list'):
                return {issued[0] + '/': {'accessor': 'selected'}}
            if path == 'identity/group':
                return {'data': {'id': 'group-id'}}
            if '/login/' in path:
                return {'auth': {'entity_id': 'entity-id', 'client_token': 'login-sentinel', 'accessor': 'login-accessor'}}
            if path.startswith('oci/exchange/'):
                if fail_exchange:
                    raise dev.SafeError('Simulated exchange failure')
                return {'data': {'rpst_token': 'oci-sentinel', 'resolved_subject_token_claims': {
                    'entity_ref': 'entity-id', 'entity_name': 'test', 'mount_type': 'wrong' if bad_claims else 'oci',
                    'vault_alias_mount_accessor': 'selected', 'vault_alias_mount_type': 'userpass', 'group_list': issued[0]}}}
            if cleanup_failure and args[:2] == ('auth', 'disable'):
                raise dev.SafeError('Simulated cleanup failure')
            return {}
        output = io.StringIO()
        with patch.object(dev, 'load_session', return_value=({}, Path('/unused'), 'root-sentinel')), patch.object(dev, 'verify_target'), patch.object(dev, 'vault', side_effect=cli), contextlib.redirect_stdout(output):
            if fail_exchange or bad_claims or cleanup_failure:
                with self.assertRaises(dev.SafeError):
                    dev.smoke()
            else:
                dev.smoke()
        self.assertEqual(calls[-1][1], ('auth', 'disable', issued[0]))
        self.assertIn(('root-sentinel', ('write', '-format=json', 'oci/config'), original), calls)
        self.assertTrue(any(c[1] == ('delete', 'identity/entity/id/entity-id') for c in calls))
        self.assertEqual(sum(c[1][-1] == 'auth/token/revoke-accessor' for c in calls), 2)
        for token, args, payload in calls:
            self.assertNotIn('sentinel', ' '.join(args))
            self.assertNotIn('password=', ' '.join(args))
        self.assertNotIn('sentinel', output.getvalue())
        self.assertNotIn('entity-id', output.getvalue())
        return issued[0]

    def test_smoke_assertions_cleanup_and_unique_resources(self):
        self.assertNotEqual(self.run_smoke(), self.run_smoke())

    def test_smoke_cleans_up_on_exchange_failure(self):
        self.run_smoke(fail_exchange=True)

    def test_smoke_fails_when_identity_claims_do_not_match(self):
        self.run_smoke(bad_claims=True)

    def test_smoke_reports_incomplete_cleanup(self):
        self.run_smoke(cleanup_failure=True)

    def test_start_creates_private_state_without_secret_arguments(self):
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / '.vault-dev'
            state.mkdir(mode=0o700)
            (root / 'bin').mkdir()
            (root / 'bin/vault-plugin-secrets-oci').write_text('test binary')
            proc = MagicMock(pid=123)
            proc.poll.return_value = None
            calls = []
            def cli(token, *args, payload=None):
                calls.append((args, payload))
                if args[0] == 'status':
                    return {'cluster_id': 'ours'}
                if args[:2] == ('token', 'lookup'):
                    return {'data': {'policies': ['root']}}
                return {}
            old_mask = os.umask(0o077)
            try:
                with patch.object(dev, 'ROOT', root), patch.object(dev, 'STATE', state), patch.object(dev, 'load_config', return_value={'domain_url':'https://example.com','client_id':'client','client_secret':'secret-sentinel'}), patch.object(dev, 'command'), patch.object(dev.socket, 'socket'), patch.object(dev, 'process_identity', return_value='managed'), patch.object(dev, 'vault', side_effect=cli), patch.object(dev.subprocess, 'Popen', return_value=proc) as spawn, contextlib.redirect_stdout(io.StringIO()) as out:
                    dev.start()
                    session, run, token = dev.load_session()
                    self.assertEqual(session['cluster'], 'ours')
                    self.assertEqual(run.stat().st_mode & 0o777, 0o700)
                    for path in (run / 'token', run / 'vault.log', state / 'session.json'):
                        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    args, kwargs = spawn.call_args
                    self.assertNotIn(token, ' '.join(args[0]))
                    self.assertEqual(kwargs['env']['VAULT_DEV_ROOT_TOKEN_ID'], token)
                    self.assertIn('-dev-no-store-token', args[0])
                    self.assertIn('-dev-listen-address=127.0.0.1:8200', args[0])
                    self.assertNotIn(token, out.getvalue())
                    self.assertNotIn('secret-sentinel', out.getvalue())
                    self.assertEqual(calls[-1][1]['client_secret'], 'secret-sentinel')
            finally:
                os.umask(old_mask)

    def test_config_reads_private_shell_settings_without_inheriting_oci_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dev.write_private(root / '.env.local', 'OCI_CLIENT_SECRET="secret-sentinel"\nOCI_SUBJECT_TOKEN_SELF_MINT_ENABLED=false\n')
            with patch.object(dev, 'ROOT', root), patch.dict(os.environ, {'OCI_CLIENT_ID':'inherited'}):
                config = dev.load_config()
            self.assertEqual(config, {'client_secret':'secret-sentinel','subject_token_self_mint_enabled':False})


    def test_failed_start_stops_child_and_removes_session_credentials(self):
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / '.vault-dev'
            state.mkdir(mode=0o700)
            (root / 'bin').mkdir()
            (root / 'bin/vault-plugin-secrets-oci').write_text('test binary')
            proc = MagicMock(pid=123)
            proc.poll.return_value = None
            def cli(token, *args, payload=None):
                if args[0] == 'status':
                    return {'cluster_id': 'ours'}
                if args[:2] == ('token', 'lookup'):
                    return {'data': {'policies': ['root']}}
                raise dev.SafeError('Simulated registration failure')
            with patch.object(dev, 'ROOT', root), patch.object(dev, 'STATE', state), patch.object(dev, 'load_config', return_value={}), patch.object(dev, 'command'), patch.object(dev.socket, 'socket'), patch.object(dev, 'process_identity', return_value='managed'), patch.object(dev, 'vault', side_effect=cli), patch.object(dev.subprocess, 'Popen', return_value=proc):
                with self.assertRaises(dev.SafeError):
                    dev.start()
            proc.terminate.assert_called_once()
            proc.wait.assert_called_once()
            self.assertFalse((state / 'session.json').exists())
            self.assertEqual(list(state.glob('run-*/token')), [])

    def test_stop_checks_process_before_killing(self):
        with patch.object(dev, 'load_session', return_value=({'pid': 123, 'process': 'ours'}, Path('/unused'), 'token')), patch.object(dev, 'process_identity', return_value='other'), patch.object(dev.os, 'kill') as kill:
            with self.assertRaises(dev.SafeError):
                dev.stop()
            kill.assert_not_called()


if __name__ == '__main__':
    unittest.main()
