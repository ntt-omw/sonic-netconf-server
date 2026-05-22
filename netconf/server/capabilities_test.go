package server

import "testing"

// TestAdvertisedBaseCapabilities locks down the <hello> capability
// advertisement policy: the server must advertise exactly the capabilities
// whose operations it implements, and must NOT advertise capabilities for
// operations it does not implement (RFC 6241 §8).
//
// This guards the capabilities-advertisement fix: ietf-netconf-monitoring
// (get-schema), writable-running (edit-config on running), xpath and the two
// base capabilities are advertised; :startup, :candidate, :validate,
// :confirmed-commit, :with-defaults, :notification, :interleave,
// :rollback-on-error and :url are not.
func TestAdvertisedBaseCapabilities(t *testing.T) {
	got := advertisedBaseCapabilities()

	want := []string{
		"urn:ietf:params:netconf:base:1.0",
		"urn:ietf:params:netconf:base:1.1",
		"urn:ietf:params:netconf:capability:writable-running:1.0",
		"urn:ietf:params:netconf:capability:xpath:1.0",
		"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring",
	}

	if len(got) != len(want) {
		t.Fatalf("advertised %d capabilities, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("capability[%d] = %q, want %q", i, got[i], w)
		}
	}

	// The server must never advertise an operation it cannot honor.
	forbidden := []string{
		"urn:ietf:params:netconf:capability:startup:1.0",
		"urn:ietf:params:netconf:capability:candidate:1.0",
		"urn:ietf:params:netconf:capability:validate:1.1",
		"urn:ietf:params:netconf:capability:confirmed-commit:1.1",
		"urn:ietf:params:netconf:capability:with-defaults:1.0",
		"urn:ietf:params:netconf:capability:notification:1.0",
		"urn:ietf:params:netconf:capability:interleave:1.0",
		"urn:ietf:params:netconf:capability:rollback-on-error:1.0",
		"urn:ietf:params:netconf:capability:url:1.0",
		"http://tail-f.com/ns/netconf/actions/1.0",
	}
	set := make(map[string]bool, len(got))
	for _, c := range got {
		set[c] = true
	}
	for _, f := range forbidden {
		if set[f] {
			t.Errorf("must not advertise unimplemented capability %q", f)
		}
	}
}
