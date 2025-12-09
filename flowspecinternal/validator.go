// Copyright (C) 2025 ThorriSnep
// Licensed under the GNU Affero General Public License v3.0 or later.
// See the LICENSE file or <https://www.gnu.org/licenses/agpl-3.0.html>.

package flowspecinternal

import (
	"errors"
	"net/netip"
)

var (
	ErrNoDestinationPrefix           = errors.New("flowspec: NLRI discarded: destination prefix component not present; operator-configured requirement violated (RFC8955-a)")
	ErrNoBestUnicast                 = errors.New("flowspec: NLRI infeasible: no valid unicast best-path exists for embedded destination; forwarding context undefined")
	ErrOriginatorValidationFailed    = errors.New("flowspec: NLRI infeasible: originator/AS_PATH validation failed against unicast best-path (RFC8955/9117-b); announce-source not authorized")
	ErrMoreSpecificFromOtherNeighbor = errors.New("flowspec: NLRI infeasible: more-specific unicast prefix advertised by different upstream AS detected (RFC8955-c); rule conflicts with routing topology")
	ErrLeftMostASMismatch            = errors.New("flowspec: NLRI rejected: eBGP AS_PATH left-most AS mismatch relative to unicast best-path (RFC9117); route-server or peer topology inconsistency")
)

// ValidateFeasibility applies the RFC8955 and RFC9117 feasibility rules
func ValidateFeasibility(fs *FlowSpecRoute, rib UnicastRIB, cfg *Config) error {
	var (
		best          *UnicastRoute
		dst           *netip.Prefix
		moreSpecifics []*UnicastRoute
	)
	if cfg == nil {
		cfg = &Config{
			AllowNoDestPrefix:   false,
			EnableEmptyOrConfed: true,
		}
	}

	// Rule a)
	dst = fs.DestPrefix
	if dst == nil {
		if !cfg.AllowNoDestPrefix {
			return ErrNoDestinationPrefix
		}
		// RFC8955: if no dst prefix and explicitly allowed, rules b) and c) are moot
		return nil
	}

	// Rule b)
	best = rib.BestPath(*dst)
	if best == nil {
		return ErrNoBestUnicast
	}
	if cfg.EnableEmptyOrConfed && !fs.FromEBGP { // only valid for iBGP and local originating routes
		if len(fs.ASPath) == 0 { // TODO: ASPathPolicy validation
			goto RuleCCheck
		}
	}
	if !best.OriginatorID.Equal(fs.OriginatorID) {
		return ErrOriginatorValidationFailed
	}

RuleCCheck:
	// Rule c)
	moreSpecifics = rib.MoreSpecifics(*dst)
	for _, r := range moreSpecifics {
		if r.NeighborAS != best.NeighborAS {
			return ErrMoreSpecificFromOtherNeighbor
		}
	}

	// RFC9117: eBGP AS_PATH left-most AS equality check.
	if fs.FromEBGP == true {
		// Only empty if the route originates from your own network. No eBGP FlowSpec route should exist
		// that has control over locally originating prefixes.
		if len(best.ASPath) == 0 {
			return ErrLeftMostASMismatch
		}
		if len(fs.ASPath) == 0 { // can't happen for eBGP, just some double-checking
			return ErrLeftMostASMismatch
		}
		if fs.ASPath[0] != best.ASPath[0] {
			return ErrLeftMostASMismatch
		}
	}
	return nil
}
