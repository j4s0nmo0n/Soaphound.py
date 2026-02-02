import argparse
import sys


def gen_cli_args():
    parser = argparse.ArgumentParser(add_help=True, description="Python based ingestor for BloodHound using ADWS")
    #parser.add_argument("connection", action="store", help="domain/user[:pass]@host", nargs='?')
    #parser.add_argument("--debug", action="store_true", help="Enable DEBUG output")
    #parser.add_argument("--ts", action="store_true", help="Add timestamp to logs")
    #parser.add_argument("--hash", action="store", metavar="NTHASH", help="NT hash for auth")
    #parser.add_argument("--output-dir", type=str, default="output", help="Répertoire de sortie pour les fichiers exportés (défaut: ./output)")
    #parser.add_argument("--adws-only", action="store_true", help="Collect computers only via ADWS (no session/RPC/SMB data)")

    #bh_group = parser.add_argument_group('BloodHound, Cache & PKI Collection')
    #bh_group.add_argument("--bloodhound", action="store_true", help="Collect fresh data and generate BloodHound JSON files.")
    #bh_group.add_argument("--bloodhound-cache-file", metavar="CACHE_FILE_PATH", help="Path to cache.json to assist BloodHound processing if fresh data is also collected.")
    #bh_group.add_argument("--cache", action="store_true", help="Create/regenerate SOAPHound compatible cache files from fresh ADWS data.")


    
    parser.add_argument('-c',
                        '--collectionmethod',
                        action='store',
                        default='Default',
                        help='Which information to collect : Default or ADWSOnly (no computer connections).')
    parser.add_argument('-d',
                        '--domain',
                        action='store',
                        required=True,
                        help='Domain to query.')
    parser.add_argument('--follow-referrals', 
                    action='store_true', 
                    default=True,
                    help='Automatically follow AD referrals to parent domains (default: True)')
    parser.add_argument('-v',
                        action='store_true',
                        help='Enable verbose output.')

    parser.add_argument("--ts", action="store_true", help="Add timestamp to logs.")


    helptext = 'NTLM is the only method supported at the moment.'

    auopts = parser.add_argument_group('authentication options', description=helptext)
    auopts.add_argument('-u',
                        '--username',
                        action='store',
                        required=True,
                        help='Username. Format: username[@domain]; If the domain is unspecified, the current domain is used.')
    auopts.add_argument('-p',
                        '--password',
                        action='store',
                        help='Password')
    auopts.add_argument('--hashes',
                        action='store',
                        help='LM:NLTM hashes')

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

    coopts.add_argument("--output-dir", type=str, default="output", help="Directory to write output files (default: output)")


    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()
    return args
