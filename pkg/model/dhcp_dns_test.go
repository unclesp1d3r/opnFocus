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

			if len(tt.servers) == 0 {
				assert.Empty(t, scope.DNSServers)
			} else {
				assert.Equal(t, tt.servers, scope.DNSServers)
			}

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

// TestDHCPScope_SetDNSServers_CopiesInput guards the synchronization
// guarantee. Retaining the caller's slice let a later write to servers[0]
// change DNSServers while the deprecated scalar kept the old value, which is
// exactly the drift the setter exists to prevent. Raised in review.
func TestDHCPScope_SetDNSServers_CopiesInput(t *testing.T) {
	t.Parallel()

	servers := []string{"10.0.0.1", "10.0.0.2"}

	var scope common.DHCPScope
	scope.SetDNSServers(servers)

	servers[0] = "192.168.99.99"

	assert.Equal(t, "10.0.0.1", scope.DNSServer, "the scalar must not follow the caller's slice")
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, scope.DNSServers,
		"the stored slice must not alias the caller's")
	assert.Equal(t, scope.DNSServers[0], scope.DNSServer, "the two must stay in sync")
}

// TestDHCPScope_SetDNSServers_DropsPlaceholders guards against phantom
// entries. Both vendors write a self-closing <dnsserver/> when nothing is
// configured, which unmarshals to "" (GOTCHAS 3.4). Keeping those would
// publish a dnsServers array of blanks that omitempty cannot suppress, and a
// placeholder ordered ahead of a real server would put "" in the deprecated
// scalar and report the scope as having no resolver at all.
func TestDHCPScope_SetDNSServers_DropsPlaceholders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		in         []string
		wantSlice  []string
		wantScalar string
	}{
		{"single placeholder", []string{""}, nil, ""},
		{"two placeholders", []string{"", ""}, nil, ""},
		{"whitespace only", []string{"   "}, nil, ""},
		{"real then placeholder", []string{"10.0.0.1", ""}, []string{"10.0.0.1"}, "10.0.0.1"},
		{"placeholder then real", []string{"", "10.0.0.1"}, []string{"10.0.0.1"}, "10.0.0.1"},
		{"placeholder between", []string{"10.0.0.1", "", "10.0.0.2"}, []string{"10.0.0.1", "10.0.0.2"}, "10.0.0.1"},
		{"padded values trimmed", []string{" 10.0.0.1 "}, []string{"10.0.0.1"}, "10.0.0.1"},
		{"nil input", nil, nil, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var scope common.DHCPScope
			scope.SetDNSServers(tt.in)

			assert.Equal(t, tt.wantSlice, scope.DNSServers, "DNSServers")
			assert.Equal(t, tt.wantScalar, scope.DNSServer, "deprecated scalar")

			if len(scope.DNSServers) > 0 {
				assert.Equal(t, scope.DNSServers[0], scope.DNSServer, "the two must stay in sync")
			}
		})
	}
}
