// Copyright (C) 2025 ThorriSnep
// Licensed under the GNU Affero General Public License v3.0 or later.
// See the LICENSE file or <https://www.gnu.org/licenses/agpl-3.0.html>.

package flowspecinternal

import (
	"net/netip"
	"slices"
	"testing"
)

func mustPrefixPtr(t *testing.T, s string) *netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Errorf("netip.ParsePrefix(%q) error = %v, want <nil>", s, err)
		t.FailNow()
	}
	return &p
}

func TestCompareFSComponentList(t *testing.T) {
	tests := []struct {
		name   string
		a      FSComponentList
		b      FSComponentList
		expect int8
	}{
		{
			name: "MissingDestComponent_Loses (RFC8955 5.1 missing component)",
			a: FSComponentList{
				Components: []FSComponent{
					{
						Type:   ComponentTypeDestinationPrefix,
						Prefix: mustPrefixPtr(t, "192.0.2.0/24"),
					},
				},
			},
			b:      FSComponentList{Components: nil},
			expect: AHasPrecedence,
		},
		{
			name: "LowerComponentType_Wins (type 2 vs type 3) (RFC8955 5.1)",
			a: FSComponentList{
				Components: []FSComponent{
					{
						Type:   ComponentTypeDestinationPrefix,
						Prefix: mustPrefixPtr(t, "192.0.2.0/24"),
					},
					{
						Type: ComponentTypeIpProtocol,
						Raw:  []byte{0x81, 0x11},
					},
				},
			},
			b: FSComponentList{
				Components: []FSComponent{
					{
						Type:   ComponentTypeDestinationPrefix,
						Prefix: mustPrefixPtr(t, "192.0.2.0/24"),
					},
					{
						Type:   ComponentTypeSourcePrefix,
						Prefix: mustPrefixPtr(t, "198.51.100.0/24"),
					},
				},
			},
			expect: BHasPrecedence,
		},
		{
			name: "DestPrefix_MoreSpecific_Wins (RFC8955 5.1 IP prefix rule)",
			a: FSComponentList{
				Components: []FSComponent{
					{
						Type:   ComponentTypeDestinationPrefix,
						Prefix: mustPrefixPtr(t, "192.0.2.0/24"),
					},
				},
			},
			b: FSComponentList{
				Components: []FSComponent{
					{
						Type:   ComponentTypeDestinationPrefix,
						Prefix: mustPrefixPtr(t, "192.0.2.0/16"),
					},
				},
			},
			expect: AHasPrecedence,
		},
		{
			name: "DstPrefix_Same_SrcPrefix_MoreSpecific_Wins (RFC8955 5.1 IP prefix rule)",
			a: FSComponentList{
				Components: []FSComponent{
					{
						Type:   ComponentTypeDestinationPrefix,
						Prefix: mustPrefixPtr(t, "192.0.2.0/24"),
					},
					{
						Type:   ComponentTypeSourcePrefix,
						Prefix: mustPrefixPtr(t, "123.0.2.0/16"),
					},
				},
			},
			b: FSComponentList{
				Components: []FSComponent{
					{
						Type:   ComponentTypeDestinationPrefix,
						Prefix: mustPrefixPtr(t, "192.0.2.0/24"),
					},
					{
						Type:   ComponentTypeSourcePrefix,
						Prefix: mustPrefixPtr(t, "123.0.2.0/24"),
					},
				},
			},
			expect: BHasPrecedence,
		},
		{
			name: "DstPrefix_EqualLength_LowerIP_Wins (RFC8955 5.1 IP value rule)",
			a: FSComponentList{
				Components: []FSComponent{
					{
						Type:   ComponentTypeDestinationPrefix,
						Prefix: mustPrefixPtr(t, "192.0.2.0/24"),
					},
				},
			},
			b: FSComponentList{
				Components: []FSComponent{
					{
						Type:   ComponentTypeDestinationPrefix,
						Prefix: mustPrefixPtr(t, "192.0.2.128/24"),
					},
				},
			},
			expect: AHasPrecedence, // X.0 < X.128
		},
		{
			name: "DstPrefix_Same_SrcPrefix_EqualLength_LowerIP_Wins (RFC8955 5.1 IP value rule)",
			a: FSComponentList{
				Components: []FSComponent{
					{
						Type:   ComponentTypeDestinationPrefix,
						Prefix: mustPrefixPtr(t, "192.0.2.0/24"),
					},
					{
						Type:   ComponentTypeSourcePrefix,
						Prefix: mustPrefixPtr(t, "123.0.2.0/16"),
					},
				},
			},
			b: FSComponentList{
				Components: []FSComponent{
					{
						Type:   ComponentTypeDestinationPrefix,
						Prefix: mustPrefixPtr(t, "192.0.2.0/24"),
					},
					{
						Type:   ComponentTypeSourcePrefix,
						Prefix: mustPrefixPtr(t, "12.0.0.0/16"),
					},
				},
			},
			expect: BHasPrecedence,
		},
		{
			name: "Prefix_EqualLength_Memcmp (RFC8955 5.1 non-prefix equal length)",
			a: FSComponentList{
				Components: []FSComponent{
					{
						Type: ComponentTypeIpProtocol,
						Raw:  []byte{0x81, 0x01},
					},
				},
			},
			b: FSComponentList{
				Components: []FSComponent{
					{
						Type: ComponentTypeIpProtocol,
						Raw:  []byte{0x81, 0x06},
					},
				},
			},
			expect: AHasPrecedence,
		},
		{
			name: "NonPrefix_EqualLength_Memcmp (RFC8955 5.1 non-prefix equal length)",
			a: FSComponentList{
				Components: []FSComponent{
					{
						Type: ComponentTypeIpProtocol,
						Raw:  []byte{0x81, 0x11},
					},
				},
			},
			b: FSComponentList{
				Components: []FSComponent{
					{
						Type: ComponentTypeIpProtocol,
						Raw:  []byte{0x01, 0x06},
					},
				},
			},
			expect: BHasPrecedence,
		},
		{
			name: "CommonPrefix_LongestStringWins (RFC8955 5.1 mixed length)",
			a: FSComponentList{
				Components: []FSComponent{
					{
						Type: ComponentTypePort,
						Raw:  []byte{0x11, 0x00, 0x16, 0x11, 0xFC, 0xE2, 0x91, 0x01, 0xBB},
					},
				},
			},
			b: FSComponentList{
				Components: []FSComponent{
					{
						Type: ComponentTypePort,
						Raw:  []byte{0x11, 0x00, 0x16, 0x91, 0xFC, 0xE2},
					},
				},
			},
			expect: AHasPrecedence,
		},
		{
			name: "NonPrefix_DifferentPrefix_LowestPrefixWins (RFC8955 5.1 mixed length)",
			a: FSComponentList{
				Components: []FSComponent{
					{
						Type: ComponentTypeIpProtocol,
						Raw:  []byte{0x01, 0x73, 0x81, 0x04},
					},
				},
			},
			b: FSComponentList{
				Components: []FSComponent{
					{
						Type: ComponentTypeIpProtocol,
						Raw:  []byte{0x81, 0x04},
					},
				},
			},
			expect: AHasPrecedence,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareFlowSpecKey(tt.a, tt.b)
			if got != tt.expect {
				t.Errorf("CompareFlowSpecKey(%v, %v) = %d, want %d", tt.a, tt.b, got, tt.expect)
			}
		})
	}
}

func TestSortFlowSpecs(t *testing.T) {
	a := FSComponentList{
		Components: []FSComponent{
			{
				Type:   ComponentTypeDestinationPrefix,
				Prefix: mustPrefixPtr(t, "192.0.2.0/24"),
			},
		},
	}
	b := FSComponentList{
		Components: []FSComponent{
			{
				Type:   ComponentTypeDestinationPrefix,
				Prefix: mustPrefixPtr(t, "192.0.2.0/16"),
			},
		},
	}
	c := FSComponentList{
		Components: []FSComponent{
			{
				Type: ComponentTypeIpProtocol,
				Raw:  []byte{0x81, 0x04},
			},
		},
	}
	d := FSComponentList{
		Components: []FSComponent{
			{
				Type: ComponentTypePort,
				Raw:  []byte{0x11, 0x00, 0x16, 0x11, 0xFC, 0xE2, 0x91, 0x01, 0xBB},
			},
		},
	}

	list := []FSComponentList{b, a, d, c}
	want := []FSComponentList{a, b, c, d}
	got := make([]FSComponentList, len(list))
	copy(got, list)
	SortFlowSpecs(got)

	if len(list) != 4 {
		t.Errorf("SortFlowSpecs(%v) len(got) = %d, want %d", list, len(got), len(want))
	}

	if !slices.EqualFunc(got, want, func(x, y FSComponentList) bool {
		return CompareFlowSpecKey(x, y) == 0
	}) {
		t.Errorf("SortFlowSpecs(%v) got = %v, want %v", list, got, want)
	}
}
