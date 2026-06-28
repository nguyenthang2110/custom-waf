package main

import (
	"net/http"
	"testing"

	"waf-project/pkg/config"
)

// adminACForTest builds the access control the same way newAdminAccessControl
// does after config defaults are applied: loopback-only allow-list, loopback
// trusted proxies, CF-Connecting-IP as the real-IP header.
func adminACForTest() *adminAccessControl {
	return newAdminAccessControl(config.AdminConfig{
		LocalOnly:      true,
		AllowedCIDRs:   []string{"127.0.0.0/8", "::1/128"},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		RealIPHeader:   "CF-Connecting-IP",
	})
}

func reqWith(remoteAddr string, header, value string) *http.Request {
	r := &http.Request{RemoteAddr: remoteAddr, Header: http.Header{}}
	if header != "" {
		r.Header.Set(header, value)
	}
	return r
}

// TestAdminAccessControl_RealIPBehindProxy locks in the fix for the tunnel
// bypass: when the WAF sits behind a local proxy (cloudflared at 127.0.0.1),
// gating on RemoteAddr alone let any outsider through. The real client IP must
// come from the trusted proxy's CF-Connecting-IP header instead.
func TestAdminAccessControl_RealIPBehindProxy(t *testing.T) {
	ac := adminACForTest()

	cases := []struct {
		name       string
		remoteAddr string
		header     string
		value      string
		wantAllow  bool
	}{
		// A local admin connecting directly: no proxy header, loopback peer.
		{"local direct, no header", "127.0.0.1:50000", "", "", true},
		{"local direct ipv6", "[::1]:50000", "", "", true},

		// Outsider arriving through the local tunnel: peer is the trusted
		// proxy (127.0.0.1) but CF-Connecting-IP is a public IP → reject.
		{"tunnel outsider", "127.0.0.1:50000", "CF-Connecting-IP", "8.8.8.8", false},
		{"tunnel outsider rfc5737", "127.0.0.1:50000", "CF-Connecting-IP", "203.0.113.7", false},

		// A genuinely local client reaching the proxy still passes when the
		// real IP it forwards is itself loopback.
		{"tunnel but real ip loopback", "127.0.0.1:50000", "CF-Connecting-IP", "127.0.0.1", true},

		// Spoofing defence #1: the header is only honoured from a trusted peer.
		// A direct (non-loopback) attacker forging CF-Connecting-IP is judged
		// on their real peer address, not the forged header.
		{"direct attacker forging header", "203.0.113.50:40000", "CF-Connecting-IP", "127.0.0.1", false},

		// Spoofing defence #2: only the configured real_ip_header is trusted.
		// A local request carrying an attacker-controlled X-Forwarded-For is
		// NOT diverted — XFF is ignored entirely.
		{"local with spoofed XFF ignored", "127.0.0.1:50000", "X-Forwarded-For", "8.8.8.8", true},

		// A direct outsider with no proxy involvement is rejected as before.
		{"direct outsider", "203.0.113.50:40000", "", "", false},

		// XFF comma-list from the trusted proxy: leftmost is the real client.
		{"tunnel xff-style list", "127.0.0.1:50000", "CF-Connecting-IP", "8.8.8.8, 127.0.0.1", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ac.check(reqWith(tc.remoteAddr, tc.header, tc.value))
			if got != tc.wantAllow {
				t.Fatalf("check()=%v, want %v (remote=%s %s:%s)",
					got, tc.wantAllow, tc.remoteAddr, tc.header, tc.value)
			}
		})
	}
}

// TestAdminAccessControl_Disabled confirms the gate is identity when local_only
// is off — every request passes regardless of origin.
func TestAdminAccessControl_Disabled(t *testing.T) {
	ac := newAdminAccessControl(config.AdminConfig{LocalOnly: false})
	if !ac.check(reqWith("203.0.113.50:40000", "", "")) {
		t.Fatal("disabled gate must allow all requests")
	}
}
