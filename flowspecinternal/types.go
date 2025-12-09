// Copyright (C) 2025 ThorriSnep
// Licensed under the GNU Affero General Public License v3.0 or later.
// See the LICENSE file or <https://www.gnu.org/licenses/agpl-3.0.html>.

package flowspecinternal

import (
	"net"
	"net/netip"
)

// FlowSpecRoute represents the bits we need for RFC8955/9117 feasibility.
// ToDo: extend, e.g. src prefix or segments
type FlowSpecRoute struct {
	DestPrefix   *netip.Prefix
	FromEBGP     bool
	NeighborAS   uint32
	ASPath       []uint32
	OriginatorID net.IP
}

// UnicastRoute is the minimal info we need from the unicast RIB.
type UnicastRoute struct {
	Prefix       netip.Prefix
	NeighborAS   uint32 // Support for rfc6793
	ASPath       []uint32
	OriginatorID net.IP
}

// UnicastRIB ToDo: intended to be an interface to operations performed on RIB
type UnicastRIB interface {
	BestPath(p netip.Prefix) *UnicastRoute
	MoreSpecifics(p netip.Prefix) []*UnicastRoute
}

// Config to reflect options in RFC ToDo: extend with options for user
type Config struct {
	// AllowNoDestPrefix as per RFC8955 6.
	// "However, rule a MAY be relaxed by explicit configuration"
	AllowNoDestPrefix bool

	// EnableEmptyOrConfed as per RFC 9117 4.1 b) 2.1
	EnableEmptyOrConfed bool

	// ASPathPolicy as per RFC9117 4.1 b) 2.3
	ASPathPolicy ASPathPolicy
}

// ASPathPolicy ToDo: Implement, for now just a stub
type ASPathPolicy interface {
	Allows(asPath []uint32) bool
}

// ComponentType corresponds to the RFC8955 component type octet.
type ComponentType uint8

const (
	ComponentTypeDestinationPrefix ComponentType = 1
	ComponentTypeSourcePrefix      ComponentType = 2
	ComponentTypeIpProtocol        ComponentType = 3
	ComponentTypePort              ComponentType = 4
	// TODO: ComponentType 5 to 12
)

// FSComponent represents a single FlowSpec NLRI component as per RFC8955 4.2.2.
//
// For type 1/2, Prefix is used.
// For all other types, Raw is used to
// carrie the NLRI-encoded "value" bytes for comparison as per RFC8955 section 5.1
type FSComponent struct {
	Type   ComponentType
	Prefix *netip.Prefix
	Raw    []byte
}

// FSComponentList is the RFC8955 "component list" view for ordering.
type FSComponentList struct {
	Components []FSComponent
}
