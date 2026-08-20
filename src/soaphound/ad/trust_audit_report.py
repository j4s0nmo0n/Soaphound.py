#!/usr/bin/env python3
"""Human-readable trust audit report generator for Soaphound.py.

Consumes the enriched trust dicts produced by
soaphound.ad.collectors.trust.trust_to_audit_output() and produces a text
file summarizing:
  - Trust identification (partner, direction, type, SID)
  - The 4 Sandker dimensions (transitivity, SID filtering mode, TGT
    delegation, authentication level)
  - Raw trustAttributes value and decoded flag names
  - Detected security risks with severity, description, and reference URL
  - A general references section for the auditor to dig deeper

References:
  - https://www.thehacker.recipes/ad/movement/trusts/
  - https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/
  - https://offsec.almond.consulting/trust-no-one_are-one-way-trusts-really-one-way.html
  - https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/
"""

import os
import datetime


# Colored severity labels for terminal display (optional - the file itself is plain text)
_SEVERITY_ORDER = {'HIGH': 0, 'MEDIUM': 1, 'INFO': 2}


def _severity_sort_key(risk):
    """Sort risks by severity (HIGH first, INFO last)."""
    return _SEVERITY_ORDER.get(risk.get('severity', 'INFO'), 99)


def _wrap_text(text, width=75, indent="      "):
    """Simple word-wrap for description paragraphs."""
    words = text.split()
    lines = []
    current = indent
    for word in words:
        if len(current) + len(word) + 1 > width + len(indent):
            lines.append(current.rstrip())
            current = indent + word
        else:
            current += (" " if current != indent else "") + word
    if current.strip():
        lines.append(current.rstrip())
    return "\n".join(lines)


def _format_trust_section(index, trust):
    """Render one trust as a text section."""
    lines = []
    partner = trust.get('TargetDomainName', '(unknown)')
    source = trust.get('_source_domain_name', '')
    header = f"[Trust {index}] {partner}"
    if source:
        header += f"  (TDO seen from {source.upper()})"
    lines.append(header)
    lines.append("-" * 65)

    # Identification
    lines.append(f"  Direction:            {trust.get('TrustDirection', 'Unknown')}")
    lines.append(f"  Type:                 {trust.get('TrustType', 'Unknown')}")
    sid = trust.get('TargetDomainSid', '') or '(not available)'
    lines.append(f"  SID:                  {sid}")
    lines.append("")

    # Sandker dimensions
    lines.append("  Dimensions (per Sandker's rules):")
    lines.append(f"    Transitivity:       {trust.get('Transitivity')}")
    lines.append(f"    SID Filtering:      {trust.get('SIDFilteringMode')}")
    lines.append(f"    TGT Delegation:     {trust.get('TGTDelegation')}")
    lines.append(f"    Auth Level:         {trust.get('AuthenticationLevel')}")
    lines.append("")

    # Attributes
    raw = trust.get('AttributesRaw', 0)
    flags = trust.get('AttributesFlags', []) or []
    lines.append(f"  Attributes (raw = 0x{raw:x}):")
    if flags:
        for f in flags:
            lines.append(f"    {f}")
    else:
        lines.append("    (no flags set)")
    lines.append("")

    # Risks
    risks = trust.get('AuditRisks', []) or []
    if risks:
        risks_sorted = sorted(risks, key=_severity_sort_key)
        lines.append(f"  Risks ({len(risks_sorted)} detected):")
        for r in risks_sorted:
            severity = r.get('severity', 'INFO')
            rid = r.get('id', '?')
            name = r.get('name', '')
            lines.append(f"    [{severity}] {rid} - {name}")
            desc = r.get('description', '')
            if desc:
                lines.append(_wrap_text(desc, width=65, indent="      "))
            ref = r.get('reference', '')
            if ref:
                lines.append(f"      Reference: {ref}")
            lines.append("")
    else:
        lines.append("  Risks: none detected")
        lines.append("")

    return "\n".join(lines)


def _format_header(domain_name, trust_count):
    """Render the report header."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 65,
        "  Soaphound.py - Trust Audit Report",
        "=" * 65,
        f"  Generated:      {now}",
        f"  Source domain:  {(domain_name or '').upper() or '(unknown)'}",
        f"  Trusts:         {trust_count}",
        "=" * 65,
        "",
    ]
    return "\n".join(lines)


def _format_footer():
    """Render the references footer."""
    lines = [
        "=" * 65,
        "  References",
        "=" * 65,
        "  Trust theory & audit:",
        "    https://www.thehacker.recipes/ad/movement/trusts/",
        "    https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/",
        "    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c",
        "",
        "  Attack techniques:",
        "    https://offsec.almond.consulting/trust-no-one_are-one-way-trusts-really-one-way.html",
        "    https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/",
        "    https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/",
        "    https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/",
        "    https://blog.harmj0y.net/redteaming/not-a-security-boundary-breaking-forest-trusts/",
        "",
        "  SID filtering deep-dive (improsec series):",
        "    https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-3-sid-filtering-explained",
        "    https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research",
        "",
        "  Tools:",
        "    https://github.com/AlmondOffSec/tdo_dump  (one-way trust TDO extraction)",
        "    https://github.com/dirkjanm/forest-trust-tools",
        "=" * 65,
    ]
    return "\n".join(lines)


def _compute_stats(audit_trusts):
    """Aggregate risk counts across all trusts."""
    stats = {'HIGH': 0, 'MEDIUM': 0, 'INFO': 0}
    for t in audit_trusts:
        for r in (t.get('AuditRisks') or []):
            sev = r.get('severity', 'INFO')
            stats[sev] = stats.get(sev, 0) + 1
    return stats


def _format_summary(stats, trust_count):
    """Render summary counters."""
    lines = [
        "  Summary:",
        f"    Trusts analyzed:    {trust_count}",
        f"    HIGH severity:      {stats.get('HIGH', 0)}",
        f"    MEDIUM severity:    {stats.get('MEDIUM', 0)}",
        f"    INFO severity:      {stats.get('INFO', 0)}",
        "",
    ]
    return "\n".join(lines)


def generate_trust_audit_report(audit_trusts, domain_name=None, output_dir=".", prefix=None):
    """Generate a human-readable trust audit report file.

    Args:
        audit_trusts: list of dicts produced by trust_to_audit_output()
        domain_name: source domain name (for report header)
        output_dir: directory where the report file will be written
        prefix: optional string to prepend to the filename (matches -op flag)

    Returns:
        Absolute path of the generated report file.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    prefix_part = f"{prefix}_" if prefix else ""
    filename = f"{timestamp}_{prefix_part}Soaphound_TrustsAudit.txt"

    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)

    # Build report content
    parts = []
    parts.append(_format_header(domain_name, len(audit_trusts)))

    stats = _compute_stats(audit_trusts)
    parts.append(_format_summary(stats, len(audit_trusts)))

    if audit_trusts:
        for i, trust in enumerate(audit_trusts, start=1):
            parts.append(_format_trust_section(i, trust))
    else:
        parts.append("  No trusts to analyze.")
        parts.append("")

    parts.append(_format_footer())

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))
        f.write("\n")

    return os.path.abspath(output_path)
