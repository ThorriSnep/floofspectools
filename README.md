### floofspectools

A small Go module to validate FlowSpec routes against a local unicast RIB.
The code is oriented toward correctness and testability.
The implementation of the RFC 8955/9117 validation procedure and RFC 8955 ordering is meant to follow the RFC exactly.

### Requirements
- Go 1.25

### Project structure
```
.
├─ go.mod
├─ main.go                     # Placeholder
└─ flowspecinternal/           # Library code
   ├─ types.go                 # Core types and interfaces (FlowSpecRoute, UnicastRoute, FSComponent, etc.)
   ├─ ordering.go              # RFC8955 ordering: CompareFlowSpecKey, SortFlowSpecs
   ├─ ordering_test.go         # Ordering tests
   ├─ validator.go             # RFC8955/9117 feasibility: ValidateFeasibility
   └─ validator_test.go        # Feasibility tests
```

### Overview of flowspecinternal
- Types:
  - `FlowSpecRoute`, `UnicastRoute`, `UnicastRIB` (interface), `Config`
  - `FSComponent`, `FSComponentList`, `ComponentType`
- Ordering (RFC 8955 5.1):
  - `CompareFlowSpecKey(a, b FSComponentList) int8`
  - `SortFlowSpecs(list []FSComponentList)` sorts in highest‑precedence‑first order
- Feasibility (RFC 8955/9117):
  - `ValidateFeasibility(fs *FlowSpecRoute, rib UnicastRIB, cfg *Config) error`
  - Returns rich error values such as `ErrNoDestinationPrefix`, `ErrNoBestUnicast`, `ErrOriginatorValidationFailed`, `ErrMoreSpecificFromOtherNeighbor`, `ErrLeftMostASMismatch`

### ToDo

a lot x.x

### License

floofspectools is licensed under the GNU Affero General Public License v3.0 (AGPLv3).
