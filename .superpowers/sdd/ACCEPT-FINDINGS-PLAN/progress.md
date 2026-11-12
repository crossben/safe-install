# SDD ledger — plan: /tmp/claude-1000/-home-ben-hattab-Desktop-GrIgRa-safe-install/0e9388f3-d8b7-424b-a626-da9cf9d096ce/scratchpad/ACCEPT-FINDINGS-PLAN.md

## Setup

**Pre-flight interface scan:**
- Task 1 (Policy) → Produces: Acceptance struct, LookupAcceptance, AcceptFinding, RevokeFinding
  - Task 2 (Finding) consumes: Acceptance struct ✓
  - Task 3 (Scan) consumes: LookupAcceptance ✓
  - Task 5 (Commands) consumes: all Task 1 outputs ✓
  - Task 6 (accept cmd) consumes: AcceptFinding, RevokeFinding ✓
  - Task 9 (Stale) consumes: policy with AcceptFindings ✓
  - Status: consistent

- Task 2 (Finding) → Produces: Finding.Accepted field
  - Task 3 (Scan) consumes: Finding.Accepted ✓
  - Task 4 (Formatters) consumes: Finding.Accepted ✓
  - Status: consistent

- Task 3 (Scan) → Produces: ApplyAcceptances, CountByStatus
  - Task 5 (Commands) consumes: ApplyAcceptances ✓
  - Task 4 (Formatters) consumes: CountByStatus ✓
  - Status: consistent

- Task 4 (Formatters) → Produces: text/JSON/SARIF output with acceptance markers
  - Task 5 (Commands) consumes: formatters ✓
  - Task 7 (Action) consumes: formatters ✓
  - Status: consistent

- Task 6 (accept cmd) → Produces: CLI command registered in main.go
  - Task 7 (Action) inherits automatically ✓
  - Status: consistent

- Task 10 (optional PowerShell) → Consumes: codescan rules
  - Status: independent, can be skipped or done last

**Global constraints verified:**
- Version floor: Go 1.25+ ✓
- Hash pinning on package+version+rule+file+hash ✓
- TTY requirement for accept ✓
- Org policy enforcement possible ✓
- Summary format specified ✓
- Backward compatibility required ✓

---

## Task Progress

**Task 1: Policy layer** - COMPLETE (10/10 steps done, all tests pass)
- Acceptance struct defined with Version, Rule, File, Hash, Reason, By, At, Expires fields
- Implemented Acceptance.Expired() and Acceptance.Validate()
- Implemented Policy.LookupAcceptance() for exact matching on pkg+ver+rule+file+hash
- Implemented AcceptFinding() and RevokeFinding() functions
- Updated File struct with AcceptFindings map
- Updated policy Load, Read, overlay, update functions
- All tests pass: 27 total tests in policy package, including new acceptance tests

**Task 2: Finding struct - Ruling: Use interface{} instead of *policy.Acceptance**
- Reason: Go struct literals don't support partial positional arguments. Adding a typed field breaks 15+ existing Finding creations in rules.go that use positional syntax.
- Decision: Use interface{} as the Accepted field type to avoid import dependency and allow any future acceptance type. This keeps existing code working without modification.
- Cost if wrong: Type safety lost for Accepted field, but acceptable since it's omitempty and for internal use only.

