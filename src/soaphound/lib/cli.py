import argparse
import sys


def gen_cli_args():
    parser = argparse.ArgumentParser(add_help=True, description="Python based ingestor for BloodHound using ADWS")
    #parser.add_argument("connection", action="store", help="domain/user[:pass]@host", nargs='?')
    #parser.add_argument("--debug", action="store_true", help="Enable DEBUG output")
    #parser.add_argument("--ts", action="store_true", help="Add timestamp to logs")
    #parser.add_argument("--hash", action="store", metavar="NTHASH", help="NT hash for auth")
    #parser.add_argument("--output-dir", type=str, default="output", help="Output directory for exported files (default: ./output)")
    #parser.add_argument("--adws-only", action="store_true", help="Collect computers only via ADWS (no session/RPC/SMB data)")

    #bh_group = parser.add_argument_group('BloodHound, Cache & PKI Collection')
    #bh_group.add_argument("--bloodhound", action="store_true", help="Collect fresh data and generate BloodHound JSON files.")
    #bh_group.add_argument("--bloodhound-cache-file", metavar="CACHE_FILE_PATH", help="Path to cache.json to assist BloodHound processing if fresh data is also collected.")
    #bh_group.add_argument("--cache", action="store_true", help="Create/regenerate SOAPHound compatible cache files from fresh ADWS data.")



    parser.add_argument('-c',
                        '--collectionmethod',
                        action='store',
                        default='Default',
                        choices=('Default', 'Stealth', 'ADWSOnly'),
                        help=(
                            "Collection preset. "
                            "Default: AD objects via ADWS (TCP:9389) + GPO settings via SMB SYSVOL (TCP:445). "
                            "Richest BloodHound output. "
                            "Stealth: ADWS-strict (TCP:9389 only, including referral follow). "
                            "Skips SYSVOL, so GPO settings, local admins and GPP cpassword are not collected. "
                            "Use when SMB is blocked or monitored. "
                            "ADWSOnly: deprecated alias of Stealth, will be removed in v1.5."
                        ))
    parser.add_argument('-d',
                        '--domain',
                        action='store',
                        required=False,
                        help='Domain to query (extrait du ccache en mode -k si non fourni).')
    parser.add_argument('-v',
                        action='store_true',
                        help='Enable verbose output.')

    parser.add_argument("--ts", action="store_true", help="Add timestamp to logs.")


    helptext = 'NTLM (utilisateur/mot de passe ou hash NT) ou Kerberos (-k via KRB5CCNAME).'

    auopts = parser.add_argument_group('authentication options', description=helptext)
    auopts.add_argument('-u',
                        '--username',
                        action='store',
                        required=False,
                        help='Username. Format: username[@domain]; If the domain is unspecified, the current domain is used.')
    auopts.add_argument('-p',
                        '--password',
                        action='store',
                        help='Password')
    auopts.add_argument('--hashes',
                        action='store',
                        help='LM:NLTM hashes')
    auopts.add_argument('-k',
                        '--kerberos',
                        action='store_true',
                        help='Kerberos authentication using the ticket in the ccache pointed to by KRB5CCNAME.')
    auopts.add_argument('-aesKey',
                        '--aes-key',
                        action='store',
                        metavar='HEXKEY',
                        help='AES key (128/256 bits) for Kerberos authentication (used for SMB collection in Default mode).')
    auopts.add_argument('-dc-ip',
                        '--kdc-ip',
                        action='store',
                        metavar='HOST',
                        help='KDC IP/host. Useful when the ADWS DC and the KDC differ (default: value of -dc).')

    coopts = parser.add_argument_group('collection options')

    coopts.add_argument('-dc',
                        '--domain-controller',
                        metavar='HOST',
                        action='store',
                        required=True,
                        help='DC to query (hostname)')

    coopts.add_argument('--zip',
                        action='store_true',
                        help='Compress the JSON output files into a zip archive.')

    coopts.add_argument('-op',
                        '--outputprefix',
                        metavar='PREFIX_NAME',
                        action='store',
                        help='String to prepend to output file names.')

    coopts.add_argument('-wk',
                        '--worker_num',
                        metavar='NUM_WORKERS',
                        action='store',
                        default=100,
                        help='Number of workers, default 100')

    coopts.add_argument("--output-dir", type=str, default=".", help="Output folder (default .).")

    coopts.add_argument(
        "--cert-find",
        action="store_true",
        help="Enumerate AD CS certificate templates and CAs like certipy find."
    )
    coopts.add_argument(
        "--trust-audit",
        action="store_true",
        help="Audit AD trusts: decode trustAttributes flags per Sandker's rules (transitivity, SID filtering mode, TGT delegation, authentication level) and detect misconfigurations (intra-forest SID filter disabled, TREAT_AS_EXTERNAL relaxation, cross-forest TGT delegation, PIM trust, one-way trust reversibility per Almond). Generates <timestamp>_trusts_audit.txt in the output dir."
    )

    coopts.add_argument(
        "--cert-find-force-epa",
        choices=("auto", "enabled", "disabled"),
        default="auto",
        help="Override HTTPS EPA detection for AD CS Web Enrollment: auto, enabled, or disabled."
    )

    coopts.add_argument(
        "--cert-find-skip-web-probe",
        action="store_true",
        help="Do not probe HTTP/HTTPS /certsrv/ endpoints. AD CS Web Enrollment and ESC8 will not be evaluated."
    )

    coopts.add_argument(
        "--cert-find-skip-ca-rpc",
        action="store_true",
        help="Skip Remote Registry/RPC enrichment of CA configuration. By default the RPC lookup is attempted so that vulnerabilities requiring registry values (ESC6, ESC11, RequestDisposition) can be detected. Use this to reduce network noise or when RPC is filtered."
    )
    coopts.add_argument(
        "--cert-find-ca-rpc",
        action="store_true",
        help=argparse.SUPPRESS,  # Deprecated: RPC enrichment is now on by default.
    )

    # MS-ADCAP TopologyManagement primitives (MS-ADCAP 3.2.4). Mutually
    # exclusive with each other and with the BloodHound collect path:
    # soaphound.py:main dispatches on these early and exits before touching
    # the collectors.
    adcap_group = parser.add_argument_group(
        "adcap options",
        description="MS-ADCAP TopologyManagement primitives (RSAT PowerShell equivalents).",
    )
    adcap_mex = adcap_group.add_mutually_exclusive_group()
    adcap_mex.add_argument(
        "--adcap-get-forest",
        action="store_true",
        help="Call MS-ADCAP GetADForest on the configured domain and print the response as JSON.",
    )
    adcap_mex.add_argument(
        "--adcap-translate",
        metavar="NAME",
        action="store",
        default=None,
        help="Call MS-ADCAP TranslateName on NAME (default: offered=NameSamCompatible=2, desired=NameFullyQualifiedDN=1).",
    )
    adcap_mex.add_argument(
        "--adcap-change-feature",
        metavar="GUID",
        action="store",
        default=None,
        help="Call MS-ADCAP ChangeOptionalFeature for the optional feature GUID (enables it by default).",
    )
    adcap_group.add_argument(
        "--adcap-change-feature-dn",
        metavar="DN",
        action="store",
        default=None,
        help="Distinguished name of the context used by --adcap-change-feature. Defaults to CN=Partitions,CN=Configuration,<rootDN> (forest-level features like the Recycle Bin). Override for feature-specific contexts.",
    )

    # BadSuccessor via ADWS (v1.5.0). Flag-based mode selector, same shape
    # as the --adcap-* options above: --badsuccessor short-circuits the
    # BloodHound collect pipeline in soaphound.py:main and runs the
    # dedicated orchestrator instead. See README section "BadSuccessor via
    # ADWS" and the design doc for the full operation list.
    badsuccessor_group = parser.add_argument_group(
        "badsuccessor options",
        description="BadSuccessor via ADWS: three AD writes against the Resource/ResourceFactory endpoints on net.tcp:9389 to create a dMSA that supersedes a target principal. Based on Yuval Gordon / Akamai advisory (2024).",
    )
    badsuccessor_group.add_argument(
        "--badsuccessor",
        action="store_true",
        help="Run the BadSuccessor ADWS orchestrator. Requires --target, --dmsa-cn and --dmsa-ou.",
    )
    badsuccessor_group.add_argument(
        "--target",
        metavar="DN",
        action="store",
        default=None,
        help="Distinguished Name of the AD principal to supersede (written to msDS-ManagedAccountPrecededByLink on the new dMSA).",
    )
    badsuccessor_group.add_argument(
        "--dmsa-cn",
        metavar="CN",
        action="store",
        default=None,
        help="Common name of the dMSA to create. sAMAccountName is derived as '<cn>$'.",
    )
    badsuccessor_group.add_argument(
        "--dmsa-ou",
        metavar="OU_DN",
        action="store",
        default=None,
        help="Distinguished Name of the OU under which the dMSA is created. Caller must have Create Child for the msDS-DelegatedManagedServiceAccount class on this OU.",
    )
    badsuccessor_group.add_argument(
        "--dry-run",
        action="store_true",
        help="BadSuccessor only: render and log the three SOAP payloads without sending them. Useful for permission-matrix debugging and demos.",
    )
    badsuccessor_group.add_argument(
        "--rollback",
        action="store_true",
        help="BadSuccessor only: on a failed Op 2 or Op 3, delete the partially-configured dMSA before exiting.",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()
    return args
