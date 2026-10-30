# Phase 7 Verification Script

Run this script against a case directory to verify all Phase 7 gate checks
(except examiner approval, which requires human judgment).

## Usage

```bash
cd ~/cases && python3 -c "
import sys, json, os
sys.path.insert(0, os.path.expanduser('~/forensic-kb/scripts'))
from audit import verify_chain

for case in ['NNN-casename']:
    print(f'=== {case} ===')
    
    # 1. Audit chain
    ok, msg = verify_chain(case)
    print(f'  Audit chain: {msg} ({\"PASS\" if ok else \"FAIL\"})')
    
    # 2. Audit↔disk consistency
    audit_ids = set()
    with open(f'{case}/audit.jsonl') as f:
        for line in f:
            if not line.strip(): continue
            row = json.loads(line)
            fid = row.get('finding_id')
            if fid: audit_ids.add(fid)
    
    disk_ids = set()
    findings_dir = f'{case}/findings/'
    if os.path.isdir(findings_dir):
        for fname in os.listdir(findings_dir):
            if fname.endswith('.yaml'):
                disk_ids.add(fname.replace('.yaml', ''))
    
    missing = audit_ids - disk_ids
    extra = disk_ids - audit_ids
    if missing or extra:
        print(f'  Consistency: FAIL')
        if missing: print(f'    Missing on disk: {sorted(missing)}')
        if extra:   print(f'    Extra on disk:   {sorted(extra)}')
    else:
        print(f'  Consistency: PASS ({len(audit_ids)} refs = {len(disk_ids)} files)')
    
    # 3. Approval audit rows
    approval_rows = []
    with open(f'{case}/audit.jsonl') as f:
        for line in f:
            if not line.strip(): continue
            row = json.loads(line)
            if row.get('action') == 'approval':
                approval_rows.append(row)
    
    if approval_rows:
        for r in approval_rows:
            print(f'  Approval audit: {r[\"finding_id\"]} → {r[\"status\"]} (seq {r[\"seq\"]})')
    else:
        # Check YAML for approval without audit row
        yaml_approved = []
        if os.path.isdir(findings_dir):
            for fname in os.listdir(findings_dir):
                if fname.endswith('.yaml'):
                    with open(os.path.join(findings_dir, fname)) as yf:
                        content = yf.read()
                    if 'approval: APPROVED' in content or 'approval: SUPERSEDED' in content or 'approval: REJECTED' in content:
                        yaml_approved.append(fname)
        if yaml_approved:
            print(f'  Approval audit: MISSING — YAMLs have approval fields but no audit rows: {yaml_approved}')
            print(f'    This is a chain-of-custody gap. Approvals outside the hash chain are unverifiable.')
        else:
            print(f'  Approval audit: N/A (no findings approved yet)')
    
    # 4. Evidence read-only
    evidence_dir = f'{case}/evidence/'
    if os.path.isdir(evidence_dir):
        for fname in os.listdir(evidence_dir):
            fpath = os.path.join(evidence_dir, fname)
            if os.path.isfile(fpath):
                mode = oct(os.stat(fpath).st_mode)[-3:]
                ok = mode in ('444', '400')
                print(f'  Evidence {fname}: {mode} {\"PASS\" if ok else \"WRITABLE\"}')
    
    # 5. Cross-case index presence
    index_path = 'index.md'
    if os.path.exists(index_path):
        with open(index_path) as f:
            if case in f.read():
                print(f'  Cross-case index: PRESENT')
            else:
                print(f'  Cross-case index: MISSING')
    print()
"
```

## Output Interpretation

- **Audit chain FAIL**: The SHA-256 chain is broken. Most likely cause: audit rows
  were edited by hand. The entire chain must be rebuilt from a clean run.
- **Consistency FAIL (missing on disk)**: Phantom refs — audit.jsonl references
  findings whose YAML files were deleted. Caused by re-running emit multiple
  times during debugging (audit.jsonl is append-only; findings/ overwrites).
  Fix: reset case and re-run from Phase 0.
- **Consistency FAIL (extra on disk)**: YAML files exist with no audit reference.
  They were created outside the pipeline. Remove them or re-emit through the
  pipeline for audit traceability.
- **Approval audit MISSING**: YAMLs have `approval:` fields but no corresponding
  `action=approval` rows in audit.jsonl. This means the approval decision
  happened outside the hash chain — anyone can flip APPROVED→REJECTED or
  rewrite `approved_by` and `verify_chain()` still returns ok. Fix: record each
  decision only with `spectre approve --case <case_dir> --finding F-… --examiner
  NAME --decision APPROVED|REJECTED|SUPERSEDED --rationale TEXT` (add
  `--superseded-by F-…` for SUPERSEDED). It writes the chained `approval` row
  bound to the new YAML hash before landing the edit. Never hand-append an
  `approval` row with `audit.py append()` and never hand-edit the `approval:`
  field: a finding whose bytes are not bound by a `spectre approve` row fails
  `verify_full` Check 8, and a hand-written authority-shaped row is a forged
  record. Report the gap to the examiner; do not repair it yourself.
- **Evidence WRITABLE**: Chain-of-custody violation. Stop and report it to the
  examiner; `chmod 444` it only with their approval, and do not append an
  audit row by hand. Every phase entry re-hashes each copy and re-runs the
  guard (`custody.enforce_evidence`), recording `evidence_tampered` on a
  mismatch.

## Known Limitations

This script is a complement to `verify_chain()`, not a replacement. It checks:
1. SHA-256 prev_hash chain (via audit.py)
2. Audit↔disk consistency (finding YAML existence)
3. Approval audit trail (approval rows in chain)
4. Evidence file permissions
5. Cross-case index presence

It does NOT check:
- Whether every finding went through adversarial review (Phase 5)
- Whether case_id in audit rows matches the case directory name
- Whether MITRE techniques are in the allowed set
- Whether confidence matches the source-count formula

For the adversarial review and case_id checks, inspect audit.jsonl directly:
```bash
# Check case_id consistency
grep '"case_id"' audit.jsonl | sort -u

# Verify adversarial review ran (Phase 5)
grep '"action":"note"' audit.jsonl | grep adversarial
```

## verify_chain() Scoping Caution

`verify_chain()` validates SHA-256 prev_hash linkage only. It does NOT check:
- Case attribution (case_id in rows vs directory name)
- Audit↔disk consistency (finding YAML existence)
- Approval audit trail (approval rows present)
- Whether every finding went through all safety-critical phases

"Chain intact" and "47% of rows are misattributed to wrong case" can both be
true simultaneously — `case_id` is just another hashed field in the chain.
Presenting verify_chain() results alongside integrity checkmarks without
noting these gaps is misleading. Always run the full consistency checks above
and report verify_chain() as verifying hash linkage, not full integrity.

## Report Accuracy

When reporting Phase 7 gate results, every number must be verified against
actual audit data — never from memory or from a prior report's assertion.
This session's Phase 7 report contained four factual errors caught by
adversarial review:

| Claim | Reported | Actual |
|-------|----------|--------|
| 002 audit rows | 16 | 15 |
| 002 mis-attributed rows | 3 | 7 |
| 002 stripped violations | "2 C2 + 1 narrative" | "1 C2 + 2 narrative" |
| 004 stripped violations | "2 fabricated C2 claims" | "1 C2 + 1 narrative" |

Always grep the audit.jsonl and count before reporting.
