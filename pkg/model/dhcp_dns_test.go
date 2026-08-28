package model_test

import (
	"testing"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
	"github.com/stretchr/testify/assert"
)

// TestDHCPScope_SetDNSServers pins the invariant that keeps the deprecated
// DNSServer field usable while it is still published: it always mirrors the
// first entry of DNSServers, so the two cannot drift.
func TestDHCPScope_SetDNSServers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		servers []string
		want    string
	}{
		{"none", nil, ""},
		{"empty slice", []string{}, ""},
		{"one", []string{"192.168.1.1"}, "192.168.1.1"},
		{"several keeps the first", []string{"91.239.100.100", "89.233.43.71"}, "91.239.100.100"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var scope common.DHCPScope
			scope.SetDNSServers(tt.servers)

			assert.Equal(t, tt.servers, scope.DNSServers)
			assert.Equal(t, tt.want, scope.DNSServer,
				"the deprecated field must mirror the first entry")
		})
	}
}

// TestDHCPScope_SetDNSServers_ClearsStaleValue guards the reset: setting an
// empty list after a populated one must not leave the old scalar behind.
func TestDHCPScope_SetDNSServers_ClearsStaleValue(t *testing.T) {
	t.Parallel()

	scope := common.DHCPScope{}
	scope.SetDNSServers([]string{"10.0.0.1"})
	scope.SetDNSServers(nil)

	assert.Empty(t, scope.DNSServer)
	assert.Empty(t, scope.DNSServers)
}
