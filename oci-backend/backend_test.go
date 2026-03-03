package ocibackend

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func getTestBackend(t *testing.T) (*backend, logical.Storage) {
	b, err := Factory("v0.0.0-test")(context.Background(), &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: time.Hour,
			MaxLeaseTTLVal:     24 * time.Hour,
		},
	})
	require.NoError(t, err)

	return b.(*backend), &logical.InmemStorage{}
}

func TestBackend_Factory(t *testing.T) {
	t.Run("Initialize Factory", func(t *testing.T) {
		b, err := Factory("v0.0.0-test")(context.Background(), &logical.BackendConfig{})
		require.NoError(t, err)
		require.NotNil(t, b)

		require.NotNil(t, b)
	})

	t.Run("Nil Configuration", func(t *testing.T) {
		_, err := Factory("v0.0.0-test")(context.Background(), nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "configuration passed into backend is nil")
	})
}
