// Copyright (C) 2025 ThorriSnep
// Licensed under the GNU Affero General Public License v3.0 or later.
// See the LICENSE file or <https://www.gnu.org/licenses/agpl-3.0.html>.

package flowspecinternal

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

type mockRIB struct {
	best         *UnicastRoute
	moreSpecific []*UnicastRoute
}

func (m *mockRIB) BestPath(p netip.Prefix) *UnicastRoute {
	return m.best
}

func (m *mockRIB) MoreSpecifics(p netip.Prefix) []*UnicastRoute {
	return m.moreSpecific
}

type allowAllPolicy struct{}

func (allowAllPolicy) Allows(asPath []uint32) bool { return true }

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

func TestValidateFeasibility(t *testing.T) {
	tests := []struct {
		name  string
		build func() (*FlowSpecRoute, UnicastRIB, *Config, error)
	}{
		{
			name: "NoDestPrefix_Disallowed (RFC8955 a)",
			build: func() (*FlowSpecRoute, UnicastRIB, *Config, error) {
				cfg := &Config{
					AllowNoDestPrefix:   false,
					EnableEmptyOrConfed: true,
					ASPathPolicy:        allowAllPolicy{},
				}
				fs := &FlowSpecRoute{
					DestPrefix:   nil,
					FromEBGP:     false,
					ASPath:       nil,
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				return fs, &mockRIB{}, cfg, ErrNoDestinationPrefix
			},
		},
		{
			name: "NoDestPrefix_Allowed (RFC8955 a - relaxed)",
			build: func() (*FlowSpecRoute, UnicastRIB, *Config, error) {
				cfg := &Config{
					AllowNoDestPrefix:   true,
					EnableEmptyOrConfed: true,
					ASPathPolicy:        allowAllPolicy{},
				}
				fs := &FlowSpecRoute{
					DestPrefix:   nil,
					FromEBGP:     false,
					ASPath:       nil,
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				return fs, &mockRIB{}, cfg, nil
			},
		},
		{
			name: "OriginatorMatch_OK (RFC8955 6.b / RFC9117 4.1)",
			build: func() (*FlowSpecRoute, UnicastRIB, *Config, error) {
				dst := mustPrefix("192.88.99.0/24")
				fs := &FlowSpecRoute{
					DestPrefix:   &dst,
					FromEBGP:     false,
					ASPath:       []uint32{65001},
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				best := &UnicastRoute{
					Prefix:       mustPrefix("192.88.99.0/24"),
					NeighborAS:   65001,
					ASPath:       []uint32{65001},
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				cfg := &Config{
					AllowNoDestPrefix:   false,
					EnableEmptyOrConfed: true,
					ASPathPolicy:        allowAllPolicy{},
				}
				return fs, &mockRIB{best: best}, cfg, nil
			},
		},
		{
			name: "EmptyASPath_OK_with_iBGP_and_EnableEmptyOrConfed (RFC9117 4.1 b.2)",
			build: func() (*FlowSpecRoute, UnicastRIB, *Config, error) {
				dst := mustPrefix("192.88.99.0/24")
				fs := &FlowSpecRoute{
					DestPrefix:   &dst,
					FromEBGP:     false,
					ASPath:       nil,                    // empty
					OriginatorID: net.IPv4(192, 0, 2, 2), // different from unicast originator
				}
				best := &UnicastRoute{
					Prefix:       mustPrefix("192.88.99.0/24"),
					NeighborAS:   65001,
					ASPath:       []uint32{65001},
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				cfg := &Config{
					AllowNoDestPrefix:   false,
					EnableEmptyOrConfed: true, // condition b.2 enabled
					ASPathPolicy:        allowAllPolicy{},
				}
				return fs, &mockRIB{best: best}, cfg, nil
			},
		},
		{
			name: "EmptyASPath_Disallowed_when_b2_disabled",
			build: func() (*FlowSpecRoute, UnicastRIB, *Config, error) {
				dst := mustPrefix("192.88.99.0/24")
				fs := &FlowSpecRoute{
					DestPrefix:   &dst,
					FromEBGP:     false,
					ASPath:       nil,
					OriginatorID: net.IPv4(192, 0, 2, 2),
				}
				best := &UnicastRoute{
					Prefix:       mustPrefix("192.88.99.0/24"),
					NeighborAS:   65001,
					ASPath:       []uint32{65001},
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				cfg := &Config{
					AllowNoDestPrefix:   false,
					EnableEmptyOrConfed: false,
					ASPathPolicy:        allowAllPolicy{},
				}
				return fs, &mockRIB{best: best}, cfg, ErrOriginatorValidationFailed
			},
		},
		{
			name: "MoreSpecificFromDifferentNeighbor (RFC8955 6.c)",
			build: func() (*FlowSpecRoute, UnicastRIB, *Config, error) {
				dst := mustPrefix("192.88.99.0/24")
				fs := &FlowSpecRoute{
					DestPrefix:   &dst,
					FromEBGP:     false,
					ASPath:       []uint32{65001},
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				best := &UnicastRoute{
					Prefix:       mustPrefix("192.88.99.0/24"),
					NeighborAS:   65001,
					ASPath:       []uint32{65001},
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				more := &UnicastRoute{
					Prefix:       mustPrefix("192.88.99.0/25"),
					NeighborAS:   65002, // different upstream AS
					ASPath:       []uint32{65002},
					OriginatorID: net.IPv4(192, 0, 2, 3),
				}
				cfg := &Config{
					AllowNoDestPrefix:   false,
					EnableEmptyOrConfed: true,
					ASPathPolicy:        allowAllPolicy{},
				}
				rib := &mockRIB{best: best, moreSpecific: []*UnicastRoute{more}}
				return fs, rib, cfg, ErrMoreSpecificFromOtherNeighbor
			},
		},
		{
			name: "NoBestUnicast (no covering unicast route) (RFC8955 6.b preamble)",
			build: func() (*FlowSpecRoute, UnicastRIB, *Config, error) {
				dst := mustPrefix("192.0.2.0/24")
				fs := &FlowSpecRoute{
					DestPrefix:   &dst,
					FromEBGP:     false,
					ASPath:       []uint32{65001},
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				cfg := &Config{
					AllowNoDestPrefix:   false,
					EnableEmptyOrConfed: true,
					ASPathPolicy:        allowAllPolicy{},
				}
				return fs, &mockRIB{best: nil}, cfg, ErrNoBestUnicast
			},
		},
		{
			name: "OriginatorMismatch_Error_no_emptyAS_shortcut",
			build: func() (*FlowSpecRoute, UnicastRIB, *Config, error) {
				dst := mustPrefix("192.88.99.0/24")
				fs := &FlowSpecRoute{
					DestPrefix:   &dst,
					FromEBGP:     false,
					ASPath:       []uint32{65001},
					OriginatorID: net.IPv4(192, 0, 2, 2),
				}
				best := &UnicastRoute{
					Prefix:       mustPrefix("192.88.99.0/24"),
					NeighborAS:   65001,
					ASPath:       []uint32{65001},
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				cfg := &Config{
					AllowNoDestPrefix:   false,
					EnableEmptyOrConfed: true,
					ASPathPolicy:        allowAllPolicy{},
				}
				return fs, &mockRIB{best: best}, cfg, ErrOriginatorValidationFailed
			},
		},
		{
			name: "MoreSpecificsSameNeighbor_OK (RFC8955 6.c)",
			build: func() (*FlowSpecRoute, UnicastRIB, *Config, error) {
				dst := mustPrefix("192.88.99.0/24")
				fs := &FlowSpecRoute{
					DestPrefix:   &dst,
					FromEBGP:     false,
					ASPath:       []uint32{65001},
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				best := &UnicastRoute{
					Prefix:       mustPrefix("192.88.99.0/24"),
					NeighborAS:   65001,
					ASPath:       []uint32{65001},
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				more1 := &UnicastRoute{
					Prefix:       mustPrefix("192.88.99.0/25"),
					NeighborAS:   65001,
					ASPath:       []uint32{65001},
					OriginatorID: net.IPv4(192, 0, 2, 3),
				}
				more2 := &UnicastRoute{
					Prefix:       mustPrefix("192.88.99.128/25"),
					NeighborAS:   65001,
					ASPath:       []uint32{65001},
					OriginatorID: net.IPv4(192, 0, 2, 4),
				}
				cfg := &Config{
					AllowNoDestPrefix:   false,
					EnableEmptyOrConfed: true,
					ASPathPolicy:        allowAllPolicy{},
				}
				rib := &mockRIB{best: best, moreSpecific: []*UnicastRoute{more1, more2}}
				return fs, rib, cfg, nil
			},
		},
		{
			name: "EmptyASPath_ZeroLenSlice_IBGP_Shortcut_OK (RFC9117 4.1 b.2)",
			build: func() (*FlowSpecRoute, UnicastRIB, *Config, error) {
				dst := mustPrefix("192.88.99.0/24")
				fs := &FlowSpecRoute{
					DestPrefix:   &dst,
					FromEBGP:     false,
					ASPath:       []uint32{}, // ! not nil
					OriginatorID: net.IPv4(192, 0, 2, 2),
				}
				best := &UnicastRoute{
					Prefix:       mustPrefix("192.88.99.0/24"),
					NeighborAS:   65001,
					ASPath:       []uint32{65001},
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				cfg := &Config{
					AllowNoDestPrefix:   false,
					EnableEmptyOrConfed: true,
					ASPathPolicy:        allowAllPolicy{},
				}
				return fs, &mockRIB{best: best}, cfg, nil
			},
		},
		{
			name: "EBGP_OriginatorAndLeftMostMatch_OK (RFC8955 6.b + RFC9117 4.2)",
			build: func() (*FlowSpecRoute, UnicastRIB, *Config, error) {
				dst := mustPrefix("192.88.99.0/24")
				fs := &FlowSpecRoute{
					DestPrefix:   &dst,
					FromEBGP:     true,
					ASPath:       []uint32{65001, 64512},
					OriginatorID: net.IPv4(192, 0, 2, 10),
				}
				best := &UnicastRoute{
					Prefix:       mustPrefix("192.88.99.0/24"),
					NeighborAS:   65001,
					ASPath:       []uint32{65001, 64496},
					OriginatorID: net.IPv4(192, 0, 2, 10),
				}
				cfg := &Config{
					AllowNoDestPrefix:   false,
					EnableEmptyOrConfed: true,
					ASPathPolicy:        allowAllPolicy{},
				}
				rib := &mockRIB{best: best}
				return fs, rib, cfg, nil
			},
		},
		{
			name: "EBGP_LeftMostASMatch_but_OriginatorMismatch_Error (RFC8955 6.b + RFC9117 4.2)",
			build: func() (*FlowSpecRoute, UnicastRIB, *Config, error) {
				dst := mustPrefix("192.88.99.0/24")
				fs := &FlowSpecRoute{
					DestPrefix:   &dst,
					FromEBGP:     true,
					ASPath:       []uint32{65001, 64512},
					OriginatorID: net.IPv4(192, 0, 2, 10),
				}
				best := &UnicastRoute{
					Prefix:       mustPrefix("192.88.99.0/24"),
					NeighborAS:   65001,
					ASPath:       []uint32{65001, 64496},
					OriginatorID: net.IPv4(192, 0, 2, 20),
				}
				cfg := &Config{
					AllowNoDestPrefix:   false,
					EnableEmptyOrConfed: true,
					ASPathPolicy:        allowAllPolicy{},
				}
				rib := &mockRIB{best: best}
				return fs, rib, cfg, ErrOriginatorValidationFailed
			},
		},
		{
			name: "EBGP_LocalOriginBestPath_Error (no external FS for local prefix) (RFC9117 4.2)",
			build: func() (*FlowSpecRoute, UnicastRIB, *Config, error) {
				dst := mustPrefix("192.88.99.0/24")
				fs := &FlowSpecRoute{
					DestPrefix:   &dst,
					FromEBGP:     true,
					ASPath:       []uint32{65001},
					OriginatorID: net.IPv4(192, 0, 2, 10),
				}
				best := &UnicastRoute{
					Prefix:       mustPrefix("192.88.99.0/24"),
					NeighborAS:   60006,
					ASPath:       []uint32{},
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				cfg := &Config{
					AllowNoDestPrefix:   false,
					EnableEmptyOrConfed: true,
					ASPathPolicy:        allowAllPolicy{},
				}
				rib := &mockRIB{best: best}
				return fs, rib, cfg, ErrOriginatorValidationFailed
			},
		},
		{
			name: "NilConfig_DefaultsWork",
			build: func() (*FlowSpecRoute, UnicastRIB, *Config, error) {
				dst := mustPrefix("192.0.2.0/24")
				fs := &FlowSpecRoute{
					DestPrefix:   &dst,
					FromEBGP:     false,
					ASPath:       []uint32{65001},
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				best := &UnicastRoute{
					Prefix:       mustPrefix("192.0.2.0/24"),
					NeighborAS:   65001,
					ASPath:       []uint32{65001},
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				return fs, &mockRIB{best: best}, nil, nil
			},
		},
		{
			name: "LeftMostASMismatch_for_eBGP (RFC9117 4.2)",
			build: func() (*FlowSpecRoute, UnicastRIB, *Config, error) {
				dst := mustPrefix("192.88.99.0/24")
				fs := &FlowSpecRoute{
					DestPrefix:   &dst,
					FromEBGP:     true,
					ASPath:       []uint32{65002, 65001},
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				best := &UnicastRoute{
					Prefix:       mustPrefix("192.88.99.0/24"),
					NeighborAS:   65001,
					ASPath:       []uint32{65001, 64512},
					OriginatorID: net.IPv4(192, 0, 2, 1),
				}
				cfg := &Config{
					AllowNoDestPrefix:   false,
					EnableEmptyOrConfed: true,
					ASPathPolicy:        allowAllPolicy{},
				}
				return fs, &mockRIB{best: best}, cfg, ErrLeftMostASMismatch
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, rib, cfg, wantErr := tt.build()
			err := ValidateFeasibility(fs, rib, cfg)
			if wantErr != nil {
				if !errors.Is(err, wantErr) {
					t.Fatalf("expected %v, got %v", wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}
