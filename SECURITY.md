# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub Security Advisories
(the repository's "Security" tab, then "Report a vulnerability"). Do not open a
public issue for a suspected vulnerability.

Include the affected version or commit, steps to reproduce, and the impact you
expect. Do not attach real case data, client data or PII.

## Scope and threat model

Evidence handled by Spectre is untrusted input. Disk images, memory captures,
packet captures, event logs and every string extracted from them may be
attacker-controlled. Parsers, extraction wrappers and report rendering should
be treated as processing hostile data, so analyze evidence on a dedicated
forensic workstation or isolated VM, never on a machine holding sensitive data.

Spectre's tamper-evidence features (hash-chained audit trail, read-only
evidence copies, finding integrity checks) raise the bar against accidental
and casual modification. They do not defend against an attacker who already
has write access as the same operating-system user.
