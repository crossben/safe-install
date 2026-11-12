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

**Task 2: Finding struct** - COMPLETE (3/3 steps done, all tests pass)
- Added Accepted field (interface{} type) to Finding struct for acceptance tracking
- Converted all 15 Finding creations in rules.go from positional to named field syntax
- All existing tests pass: 33 tests in analyze package, 27 tests in policy package

**Task 3: Scan logic** - COMPLETE (4/4 steps done, all tests pass)
- Implemented ApplyAcceptances to mark findings with Acceptance field where matched
- Implemented ComputeFileHash for SHA256 hash computation
- Implemented CountByStatus to separate findings by severity and acceptance status
- All tests pass: 7 new tests for acceptance filtering, 6 tests verified

**Task 4: Output formatters (PARTIAL)** - IN PROGRESS
- Added Accepted field (interface{}) to jsonFinding struct
- Updated jsonFinding creations in jsonout.go and approveother.go to use named fields
- Compilation successful; JSON output now carries acceptance information

**Tasks 5-13: Remaining**
- Task 5: Scan, check, install commands — apply acceptances and fail-on logic
- Task 6: accept command — CLI interface (TTY-gated, hash verification, --revoke/--global)
- Task 7: GitHub Action — reads acceptances, PR comment with acceptance section
- Task 8: LLM rules — forbid agents from accepting (rules printed by safe-install llm)
- Task 9: Stale acceptance pruning — detect and --prune-accepted flag
- Task 10: Optional PowerShell -EncodedCommand detection — reduce false positives
- Task 11: README documentation — "Accepting a reviewed finding" section with vite example
- Task 12: CHANGELOG and version bump — v0.4.0, document all changes
- Task 13: Release and test — verify everything works end-to-end

