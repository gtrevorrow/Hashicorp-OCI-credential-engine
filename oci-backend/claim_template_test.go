package ocibackend

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestTemplatesValidateEveryExpressionBeforeLookup(t *testing.T) {
	for _, suffix := range []string{"{{ forbidden.expression }}", "{{", "}}", "{{ claims..sub }}", "{{ join(vault.groups) }}", `{{ join(vault.groups, "x", "y") }}`, "{{ vault.entity..id }}", "{{ {{ vault.entity.id }}", "{{ }}"} {
		for _, mode := range []string{"role", "brokered"} {
			t.Run(mode+suffix, func(t *testing.T) {
				prefix := "{{ vault.entity.id }} "
				if mode == "brokered" {
					prefix = "{{ claims.sub }} "
				}
				template := prefix + suffix
				if mode == "role" {
					require.Error(t, validateSelfMintCustomClaimTemplate(template))
					_, err := renderSelfMintCustomClaimTemplate(template, nil, nil)
					require.Error(t, err)
					require.False(t, isSelfMintTemplateLookupError(err))
				} else {
					raw, _ := json.Marshal(map[string]string{"principal": template})
					_, err := decodeBrokeredSubjectTokenClaimMappings(string(raw))
					require.Error(t, err)
					_, err = renderBrokeredClaimTemplate(template, nil)
					require.Error(t, err)
					require.False(t, isBrokeredTemplateClaimLookupError(err))
				}
			})
		}
	}
}

func TestTemplateWritesRejectTrailingErrorsWithoutChangingStorage(t *testing.T) {
	for _, mode := range []string{"role", "brokered"} {
		t.Run(mode, func(t *testing.T) {
			b, s := getTestBackend(t)
			path, key, field, template := "role/dev", "role/dev", "self_mint_custom_claims", "{{ vault.entity.id }} {{ forbidden.expression }}"
			data := map[string]interface{}{}
			if mode == "brokered" {
				path, key, field, template = "config", "config", "brokered_subject_token_claim_mappings", "{{ claims.sub }} {{ forbidden.expression }}"
				data = map[string]interface{}{"domain_url": "https://example.com", "client_id": "test", "client_secret": "test"}
			}
			data[field] = `{"principal":"valid"}`
			resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: path, Storage: s, Data: data})
			require.NoError(t, err)
			require.False(t, resp != nil && resp.IsError(), "%v", resp)
			before, err := s.Get(context.Background(), key)
			require.NoError(t, err)
			require.NotNil(t, before)
			raw, _ := json.Marshal(map[string]string{"principal": template})
			data[field] = string(raw)
			resp, err = b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: path, Storage: s, Data: data})
			require.NoError(t, err)
			require.True(t, resp.IsError())
			after, err := s.Get(context.Background(), key)
			require.NoError(t, err)
			require.Equal(t, before.Value, after.Value)
		})
	}
}

func TestTemplateSizeAndRenderingLimits(t *testing.T) {
	for _, mode := range []string{"role", "brokered"} {
		t.Run(mode, func(t *testing.T) {
			render := func(template, value string) (string, error) {
				if mode == "role" {
					return renderSelfMintCustomClaimTemplate(template, map[string]interface{}{"vault": map[string]interface{}{"value": value}}, nil)
				}
				return renderBrokeredClaimTemplate(template, map[string]interface{}{"value": value})
			}
			out, err := render(strings.Repeat("x", maxClaimTemplateBytes), "")
			require.NoError(t, err)
			require.Len(t, out, maxClaimTemplateBytes)
			_, err = render(strings.Repeat("x", maxClaimTemplateBytes+1), "")
			require.Error(t, err)
			prefix := "vault"
			if mode == "brokered" {
				prefix = "claims"
			}
			template := "{{ " + prefix + ".value }}"
			out, err = render(template, strings.Repeat("x", maxRenderedClaimBytes))
			require.NoError(t, err)
			require.Len(t, out, maxRenderedClaimBytes)
			_, err = render("a"+template, strings.Repeat("x", maxRenderedClaimBytes))
			require.ErrorContains(t, err, "rendered claim exceeds")
		})
	}
	context := map[string]interface{}{"vault": map[string]interface{}{"groups": []interface{}{strings.Repeat("x", maxRenderedClaimBytes), "y"}}}
	_, err := renderSelfMintCustomClaimTemplate(`{{ join(vault.groups, ",") }}`, context, nil)
	require.ErrorContains(t, err, "rendered claim exceeds")
}

func TestTemplateSyntaxDoesNotRequireRuntimeData(t *testing.T) {
	require.NoError(t, validateSelfMintCustomClaimTemplate(`{{ vault.entity.id }} {{ brokered.claims.sub }} {{ join(vault.groups, ",") }}`))
	_, err := decodeBrokeredSubjectTokenClaimMappings(`{"principal":"{{ claims.user.id }}:{{ claims.org }}"}`)
	require.NoError(t, err)
	_, err = renderBrokeredClaimTemplate("{{ claims.user.id }}", nil)
	require.True(t, isBrokeredTemplateClaimLookupError(err))
	out, err := renderSelfMintCustomClaimTemplate(`{{ join(vault.groups, "\"\\") }}`, map[string]interface{}{"vault": map[string]interface{}{"groups": []interface{}{"a", "b"}}}, nil)
	require.NoError(t, err)
	require.Equal(t, "a\"\\b", out)
}
