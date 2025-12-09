// Copyright (C) 2025 ThorriSnep
// Licensed under the GNU Affero General Public License v3.0 or later.
// See the LICENSE file or <https://www.gnu.org/licenses/agpl-3.0.html>.

package flowspecinternal

import (
	"sort"
)

const (
	AHasPrecedence int8 = -1
	Equal          int8 = 0
	BHasPrecedence int8 = 1
)

// CompareFlowSpecKey compares two FlowSpecKey instances according
// to RFC8955 section 5.1 (ordering of Flow Specifications).
func CompareFlowSpecKey(a, b FSComponentList) int8 {
	alen := len(a.Components)
	blen := len(b.Components)

	if alen > blen {
		return AHasPrecedence
	}
	if blen > alen {
		return BHasPrecedence
	}
	// at this point alen == blen
	for i := 0; i < alen; i++ {
		acomp := a.Components[i]
		bcomp := b.Components[i]
		atype := acomp.Type
		btype := bcomp.Type

		if atype < btype {
			return AHasPrecedence
		}
		if btype < atype {
			return BHasPrecedence
		}
		if atype == ComponentTypeDestinationPrefix || atype == ComponentTypeSourcePrefix {
			aprefix := acomp.Prefix
			bprefix := bcomp.Prefix
			abits := aprefix.Bits()
			bbits := bprefix.Bits()
			aaddr := aprefix.Addr()
			baddr := bprefix.Addr()
			if abits > bbits {
				if bprefix.Contains(aaddr) {
					return AHasPrecedence
				}
			}
			if bbits > abits {
				if aprefix.Contains(baddr) {
					return BHasPrecedence
				}
			}
			if abits == bbits {
				if aaddr.Less(baddr) {
					return AHasPrecedence
				}
				if baddr.Less(aaddr) {
					return BHasPrecedence
				}
			}
		} else {
			araw := acomp.Raw
			braw := bcomp.Raw
			alenRaw := len(araw)
			blenRaw := len(braw)

			if alenRaw == blenRaw {
				for j := 0; j < alenRaw; j++ {
					if araw[j] < braw[j] {
						return AHasPrecedence
					}
					if braw[j] < araw[j] {
						return BHasPrecedence
					}
				}
			} else {
				// compare up to the common prefix
				commonLen := alenRaw
				if blenRaw < commonLen {
					commonLen = blenRaw
				}
				for j := 0; j < commonLen; j++ {
					if araw[j] < braw[j] {
						return AHasPrecedence
					}
					if braw[j] < araw[j] {
						return BHasPrecedence
					}
				}
				if alenRaw > blenRaw {
					return AHasPrecedence
				}
				if blenRaw > alenRaw {
					return BHasPrecedence
				}
				return BHasPrecedence
			}
		}
	}

	return Equal
}

// SortFlowSpecs sorts a slice of FlowSpecKey in-place as per RFC8955 section 5.1
func SortFlowSpecs(list []FSComponentList) {
	sort.Slice(list, func(i, j int) bool {
		return CompareFlowSpecKey(list[i], list[j]) < 0
	})
}

// TODO: func KeyFromFlowSpecRoute(fs *FlowSpecRoute) (FlowSpecKey, error)
