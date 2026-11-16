package h2fp

import (
	"context"
	"testing"
)

func TestStringMatchesKnownClients(t *testing.T) {
	tests := []struct {
		name string
		fp   Fingerprint
		want string
	}{
		{
			name: "chrome",
			fp: Fingerprint{
				Settings:     []Setting{{1, 65536}, {2, 0}, {4, 6291456}, {6, 262144}},
				WindowUpdate: 15663105,
				PseudoOrder:  []string{"m", "a", "s", "p"},
			},
			want: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
		},
		{
			name: "firefox",
			fp: Fingerprint{
				Settings:     []Setting{{1, 65536}, {4, 131072}, {5, 16384}},
				WindowUpdate: 12517377,
				Priorities:   []Priority{{StreamID: 3, Exclusive: false, DependsOn: 0, Weight: 201}},
				PseudoOrder:  []string{"m", "p", "a", "s"},
			},
			want: "1:65536;4:131072;5:16384|12517377|3:0:0:201|m,p,a,s",
		},
		{
			name: "go-net-http",
			fp: Fingerprint{
				Settings:     []Setting{{2, 0}, {4, 4194304}, {6, 10485760}},
				WindowUpdate: 1073741824,
				PseudoOrder:  []string{"a", "m", "p", "s"},
			},
			want: "2:0;4:4194304;6:10485760|1073741824|0|a,m,p,s",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fp.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStringEmptyConventions(t *testing.T) {
	// Zero value: no settings, no window update, no priority, no pseudo-headers.
	if got := (Fingerprint{}).String(); got != "|00|0|" {
		t.Errorf("zero value = %q, want %q", got, "|00|0|")
	}
	// Absent window update renders "00"; a one-priority exclusive frame renders its bit.
	fp := Fingerprint{
		Settings:    []Setting{{1, 4096}},
		Priorities:  []Priority{{StreamID: 1, Exclusive: true, DependsOn: 0, Weight: 256}},
		PseudoOrder: []string{"m", "a", "s", "p"},
	}
	if got, want := fp.String(), "1:4096|00|1:1:0:256|m,a,s,p"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestContradictsBrowser(t *testing.T) {
	const (
		// Measured real-client fingerprints (Nov 2026).
		chrome  = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
		firefox = "1:65536;4:131072;5:16384|12517377|3:0:0:201|m,p,a,s"
		safari  = "3:100;4:4194304|10420225|0|m,s,p,a"
		goNet   = "2:0;4:4194304;5:1048576;6:10485760|1073741824|0|a,m,p,s"
		curl    = "3:100;4:65536;2:0|1048510465|0|m,s,a,p"
		java    = "1:16384;2:0;3:0;4:16777216;5:16384;6:393216|33488897|0|m,s,a,p"
		// httpx copies Chrome's pseudo-header order (m,a,s,p) but sends the Python-h2
		// library's bare HEADER_TABLE_SIZE of 4096 — caught by the SETTINGS tell.
		httpx = "1:4096;2:0;4:65535;5:16384;3:100;6:65536|16777216|0|m,a,s,p"
	)
	cases := []struct {
		name string
		fp   string
		want bool
	}{
		{"chrome is a browser", chrome, false},
		{"firefox is a browser", firefox, false},
		{"safari is a browser", safari, false},
		{"go client leads with authority", goNet, true},
		{"curl order is not a browser's", curl, true},
		{"java order is not a browser's", java, true},
		{"httpx copies chrome order but sends table size 4096", httpx, true},
		{"empty fingerprint is unknown", "", false},
		{"malformed fingerprint is unknown", "garbage", false},
		{"missing pseudo-order and no library setting is unknown", "1:65536|00|0|", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ContradictsBrowser(c.fp); got != c.want {
				t.Errorf("ContradictsBrowser(%q) = %v, want %v", c.fp, got, c.want)
			}
		})
	}
}

func TestPseudoOrder(t *testing.T) {
	if got := PseudoOrder("1:65536|12517377|3:0:0:201|m,p,a,s"); got != "m,p,a,s" {
		t.Errorf("PseudoOrder = %q, want %q", got, "m,p,a,s")
	}
	if got := PseudoOrder("not|enough|fields"); got != "" {
		t.Errorf("PseudoOrder on malformed = %q, want empty", got)
	}
}

func TestContextRoundTrip(t *testing.T) {
	ctx := context.Background()
	if got := FromContext(ctx); got != "" {
		t.Errorf("bare context should yield empty fingerprint, got %q", got)
	}
	const fp = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	ctx = WithFingerprint(ctx, fp)
	if got := FromContext(ctx); got != fp {
		t.Errorf("FromContext = %q, want %q", got, fp)
	}
}
