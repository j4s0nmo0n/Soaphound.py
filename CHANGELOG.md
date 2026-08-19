# Changelog

All notable changes to Soaphound-py will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.3] - 2026-08-19

### Fixed

- **cert-find**: ESC6 and ESC11 detection now works out-of-the-box. The
  `--cert-find-ca-rpc` flag was opt-in, which meant CA-level registry
  values (`InterfaceFlags`, `EditFlags`, `RequestDisposition`) were not
  fetched by default and both detections silently produced no findings on
  vulnerable CAs. RPC-based enrichment is now enabled by default to match
  Certipy's behaviour. Added `--cert-find-skip-ca-rpc` as an opt-out for
  network-sensitive engagements. The old `--cert-find-ca-rpc` flag is
  still accepted for backwards compatibility but hidden from `--help`.

- **cert-find**: ESC17 no longer requires the template EKU to include
  Client Authentication. Previous logic incorrectly gated detection on
  a subset of "authentication capable" EKUs; the actual vulnerability
  (Application Policies injection at CSR time, CVE-2024-49019 family)
  applies to any schema v1 template with enrollee-supplied subject
  regardless of EKU. Fixed the false negative on the built-in
  `WebServer` template.

- **cert-find**: Reduce noise from ESC2/ESC3 Target Template remarks.
  Previous logic flagged every legacy AD template with
  `schema_version == 1` (10+ templates per CA on typical customer PKIs).
  Now aligned strictly on Certipy: ESC2 Target requires the Any Purpose
  EKU, ESC3 Target requires the Certificate Request Agent EKU. Optional
  v2+ "signature required with app policy" branches are preserved.

- **cert-find**: `Template Name` in the human-readable report now shows
  the LDAP `displayName` (the label admins see in `certtmpl.msc`) rather
  than the raw `cn`, matching Certipy output. The raw `cn` is kept in a
  new `Template CN` field for scripts that need the technical identifier
  used in DNs. **Breaking change** for JSON consumers reading
  `Template Name` expecting the raw `cn`.

- **trusts**: `TrustType` is now correctly derived from the
  `trustAttributes` bitfield (mirroring SharpHound/BloodHound.py) instead
  of falling back to a hard-coded `"ParentChild"`. External trusts,
  forest trusts, and unclassified trusts were previously all reported as
  `"ParentChild"`, which was a false positive on every multi-domain
  forest.

- **adws**: Pagination pull loop now correctly retries a batch that fails
  to parse. The previous code unpacked `_pull_results()` directly into
  `more_results_expected`, so a parse failure (which returns `(None,
  False)`) overwrote the flag and terminated the loop before the retry
  branch could run - silently truncating the result set with a single
  `[ERROR]` line as the only signal. Verified on the `jjk.local` lab.

- **output**: JSON output now preserves non-ASCII characters (accents,
  cyrillic, CJK) instead of escaping them (`\u00c9` etc.) which allows
  BloodHound to display and search names as they appear in AD.

## [1.1.2] - see git history

## [1.1.1] - see git history

## [1.1.0] - see git history
