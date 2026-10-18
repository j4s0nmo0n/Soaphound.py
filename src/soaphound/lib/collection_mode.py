"""Collection method preset handling for Soaphound.py.

Three presets are accepted on the command line:

    Default   AD objects via ADWS + GPO settings via SMB SYSVOL + computer
              session enumeration via SMB/RPC. Uses TCP:9389 (ADWS,
              including referral follow which also stays on ADWS) and
              TCP:445 (SMB SYSVOL + per-host sessions).

    Stealth   AD objects via ADWS only (TCP:9389). No SMB session is
              opened. SYSVOL fetch is skipped, so GPO settings, local
              admins and GPP cpassword are NOT in the output.

    ADWSOnly  Deprecated alias of Stealth, kept for backward compatibility.
              A warning is emitted and the value is remapped to Stealth
              before any downstream code sees it. Will be removed in v1.5.

Referral follow: when an ADWSReferralError is raised for a cross-NC query
the client opens a new session on the referred DC. The URL is formatted
as ldap://<fqdn>/... but the connection stays on ADWS TCP:9389. Both
Default and Stealth preserve referral follow since it is pure ADWS.
"""
import sys


STEALTH_WARNING = """
[!] Stealth mode: ADWS only (TCP:9389). The following WILL NOT be collected:
      - GPO settings (GptTmpl.inf, Groups.xml) from SYSVOL
      - User rights assignments (SeDebug, SeImpersonate, SeAssignPrimaryToken, ...)
      - Local administrators derived from GPO RestrictedGroups
      - GPP cpassword credentials
      - Computer session enumeration (SMB/RPC on each host)
    Re-run with '-c Default' for complete coverage.
"""

ADWS_ONLY_DEPRECATION = (
    "[!] '-c ADWSOnly' is deprecated and will be removed in v1.5. "
    "Use '-c Stealth' instead (same behaviour)."
)


def normalize_collection_method(options, stream=None):
    """Apply the ADWSOnly -> Stealth alias and emit the stealth warning.

    Mutates options.collectionmethod in place when it reads 'ADWSOnly'.
    The caller must invoke this once, right after argparse, before any
    collection step runs. All output goes to stream (default: stderr).
    """
    if stream is None:
        stream = sys.stderr
    if options.collectionmethod == "ADWSOnly":
        print(ADWS_ONLY_DEPRECATION, file=stream)
        options.collectionmethod = "Stealth"
    if options.collectionmethod == "Stealth":
        print(STEALTH_WARNING, file=stream)


def should_skip_sysvol(options):
    """Return True when SYSVOL collection must be skipped for this run."""
    return options.collectionmethod == "Stealth"
