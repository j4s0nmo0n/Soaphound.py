# Changelog

All notable changes to Soaphound-py will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-08-20

### Added
- **trust-audit**: New `--trust-audit` flag that produces a human-readable
  text report analyzing every AD trust in the connected forest. For each
  trust, the report decodes the four Sandker dimensions (transitivity,
  SID filtering mode, TGT delegation, authentication level) from the
  `trustAttributes` bitfield with the exact rules cited in comments, and
  flags seven common misconfigurations documented in offensive AD
  literature:
  - `TRUST-01` HIGH: intra-forest SID filtering disabled by default
    (`WITHIN_FOREST` set without `QUARANTINED_DOMAIN`)
  - `TRUST-02` HIGH: forest trust with SID filtering relaxation
    (`TREAT_AS_EXTERNAL` + `FOREST_TRANSITIVE`)
  - `TRUST-03` HIGH: cross-forest TGT delegation enabled
    (`CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION`)
  - `TRUST-04` MEDIUM: external/forest trust without `QUARANTINED_DOMAIN`
  - `TRUST-05` MEDIUM: RC4 encryption on inter-realm keys
    (`USES_RC4_ENCRYPTION`)
  - `TRUST-06` INFO: PIM trust (Bastion Forest / ESAE) - verify Shadow
    Principals in the Bastion forest
  - `TRUST-07` INFO: one-way trust reversibility via TDO extraction (per
    Almond's `tdo_dump` research)

  The audit is forest-wide by design: the forest topology is read from
  `CN=Partitions,CN=Configuration` (authoritative source, replicated
  across all DCs), and each domain NC is queried independently. If the
  connected DC does not host the target partition, `ADWSReferralError`
  is caught, the referred DC hostname is extracted, and a new ADWS
  connection is established to retry. Both sides of each trust are
  collected so the report can show, for example, `MODULO.JJK.LOCAL (TDO
  seen from JJK.LOCAL)` and `JJK.LOCAL (TDO seen from MODULO.JJK.LOCAL)`
  separately - `trustAttributes` can technically differ between the two
  TDOs and this matters for audits.

  Output is written to `<timestamp>_Soaphound_TrustsAudit.txt` next to
  the existing BloodHound JSON files. The BloodHound `domains.json`
  output is unchanged.

  References cited in the report footer: hacker.recipes, Sandker
  (securesystems.de), Almond, Dirk-jan Mollema, harmj0y, improsec.

### Fixed
- **cert-find**: Revert `Template Name` in the human-readable report back
  to the LDAP `cn` (aligned with Certipy). The v1.1.3 change was based
  on a misreading of Certipy's output convention. Empirical verification
  against Certipy 1.x source (`certipy/commands/find.py:1534-1535`)
  shows the actual mapping is `cn -> Template Name` and
  `displayName -> Display Name`. Testing on a lab with 35 templates
  confirmed Certipy emits the raw LDAP `cn` (e.g.
  `KerberosAuthentication`, `CAExchange`) as `Template Name`, not the
  displayName. The v1.1.3 mapping broke interop for pentesters copying
  names from a Soaphound report into `certipy req -template ...`, which
  expects the technical `cn`.

  The `Template CN` field introduced in v1.1.3 is removed - it now
  duplicates `Template Name`. Consumers that adapted to v1.1.3 by
  reading `Template Name` for the displayName should read `Display Name`
  instead. Consumers that adapted by reading `Template CN` for the raw
  `cn` should read `Template Name`.

  This undoes the "Breaking change" noted in v1.1.3 for `Template Name`.

### Notes
- The trust-audit feature bypasses `pull_all_ad_objects` for the
  `CN=Partitions` query because `crossRef` objects do not expose
  `distinguishedName` in their ADWS payload, which trips that helper's
  filter (it discards objects without DN). A direct
  `pull_client.pull()` + manual XML parsing works around this without
  touching the shared helper.

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
