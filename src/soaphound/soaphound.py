import logging, sys, os, getpass, json, dns.resolver, datetime, time, zipfile, base64, socket
from soaphound.lib.cli import gen_cli_args
from impacket.ldap.ldaptypes import LDAP_SID
from soaphound.ad.adws import ADWSConnect, NTLMAuth, KerberosAuth
from soaphound.ad.cache_gen import (
    pull_all_ad_objects, adws_objecttype_guid_map, generate_caches,
    _generate_individual_caches, adws_object_classes, create_and_combine_soaphound_cache,
    SOAPHOUND_LDAP_PROPERTIES, SOAPHOUND_CACHE_PROPERTIES
)
from soaphound.ad.acls import normalize_name
from soaphound.ad.collectors.cert_find import run_cert_find
from soaphound.ad.collectors.domain import collect_domains, format_domains
from soaphound.ad.collectors.container import collect_containers, format_containers
from soaphound.ad.collectors.gpo import collect_gpos, format_gpos, collect_wmi_filters
from soaphound.ad.collectors.ou import collect_ous, format_ous
from soaphound.ad.collectors.group import collect_groups, format_groups
from soaphound.ad.collectors.user import collect_users, format_users
from soaphound.ad.collectors.trust import collect_trusts, trust_to_bh_output, trust_to_audit_output, collect_forest_trusts
from soaphound.ad.collectors.gpo_sysvol import connect_sysvol, collect_gpo_sysvol_changes, compute_affected_computers

from soaphound.lib.utils import ObjectCache, DNSCache
from soaphound.lib.authentication import ADAuthentication
from soaphound.ad.collectors.computer import collect_computers, format_computers
from soaphound.ad.collectors.computer_adws import collect_computers_adws, format_computers_adws
from soaphound.lib.domain import ADDomain


def _resolve_dc_fqdn(dc_arg: str) -> str:
    """Return the FQDN of the DC. If dc_arg is already a FQDN (contains a
    dot and is not a dotted-quad IP), return as-is. If it is an IPv4
    address, do a reverse DNS lookup. Abort with a clear error if the
    lookup fails -- MS-ADCAP primitives require a DNS identity in the
    <ca:Server> header, not an IP literal (which triggers an 'Instance
    invalid' fault server-side)."""
    try:
        socket.inet_aton(dc_arg)
        is_ipv4 = True
    except OSError:
        is_ipv4 = False
    if not is_ipv4:
        return dc_arg
    try:
        fqdn, _aliases, _addrs = socket.gethostbyaddr(dc_arg)
    except OSError as exc:
        raise SystemExit(
            f"[-] MS-ADCAP primitives require a DNS hostname for the DC, "
            f"but '-dc {dc_arg}' is an IP and reverse DNS lookup failed: {exc}. "
            f"Re-run with '-dc <dc-fqdn>' (e.g. '-dc dc-curse.jjk.local')."
        )
    return fqdn


def export_bloodhound_json(data, output_path):
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(clean_bytes(data), f, indent=2, ensure_ascii=False)

def safe_export_bloodhound_json(data, output_path):
    if "meta" in data and data["meta"].get("count", 0) > 0:
        export_bloodhound_json(data, output_path)

def clean_bytes(obj):
    """Recursively traverse an object and encode all bytes to base64 for JSON."""
    if isinstance(obj, dict):
        return {k: clean_bytes(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [clean_bytes(x) for x in obj]
    elif isinstance(obj, bytes):
        return base64.b64encode(obj).decode('ascii')
    else:
        return obj

def zip_bloodhound_jsons(output_dir, timestamp,  archive_name="BloodHound.zip"):
    """
    Archive tous les fichiers .json du dossier output_dir en BloodHound.zip,
    except cache.json (case-insensitive).
    """
    archive_path = archive_name
    with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as archive:
        for fname in os.listdir(output_dir):
            if (fname.lower().endswith(".json")
                    and fname.lower().startswith(timestamp)
                    and "gpp_passwords" not in fname.lower()
                    and "privilege_rights" not in fname.lower()):
                fpath = os.path.join(output_dir, fname)
                archive.write(fpath, arcname=fname)
    print(f"Zip file created at : {archive_path}")


def _format_duration(seconds: float) -> str:
    """Format an elapsed duration for the end-of-run summary."""
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{seconds:.1f}s"
    total_seconds = int(seconds)
    minutes, secs = divmod(total_seconds, 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m {secs}s"


def main():
    options = gen_cli_args()
    start = time.monotonic()
    success = False
    try:
        # Apply ADWSOnly -> Stealth deprecation alias and emit the stealth
        # warning before any collection step runs. Both go to stderr so they
        # stay visible even without -v.
        from soaphound.lib.collection_mode import normalize_collection_method, should_skip_sysvol
        normalize_collection_method(options)

        banner = """
     .oooooo..o                                oooo                                                .o8                             
    d8P'    `Y8                                `888                                               "888                             
    Y88bo.       .ooooo.   .oooo.   oo.ooooo.   888 .oo.    .ooooo.  oooo  oooo  ooo. .oo.    .oooo888      oo.ooooo.  oooo    ooo 
     `"Y8888o.  d88' `88b `P  )88b   888' `88b  888P"Y88b  d88' `88b `888  `888  `888P"Y88b  d88' `888       888' `88b  `88.  .8'  
         `"Y88b 888   888  .oP"888   888   888  888   888  888   888  888   888   888   888  888   888       888   888   `88..8'   
    oo     .d8P 888   888 d8(  888   888   888  888   888  888   888  888   888   888   888  888   888  .o.  888   888    `888'    
    8""88888P'  `Y8bod8P' `Y888""8o  888bod8P' o888o o888o `Y8bod8P'  `V88V"V8P' o888o o888o `Y8bod88P" Y8P  888bod8P'     .8'     
                                     888                                                                     888       .o..P'      
                                    o888o                                                                   o888o      `Y8P'       
                                                                                                        (made by @belettet1m0ree)
    """
        log_format = '%(asctime)s %(levelname)s: %(name)s: %(message)s' if options.ts else '[%(levelname)s] %(message)s'

        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        stream = logging.StreamHandler(sys.stderr)
        stream.setLevel(logging.DEBUG)
        formatter = logging.Formatter(log_format)
        stream.setFormatter(formatter)
        logger.addHandler(stream)

        if options.v is True:
            logger.setLevel(logging.DEBUG)

        logging.debug(options)
        print(options)

        lm = ''
        nt = ''
        aeskey = getattr(options, 'aes_key', None) or ''
        kdc_host = getattr(options, 'kdc_ip', None) or options.domain_controller

        # ------------------------------------------------------------------
        # Selection du mode d'authentification (NTLM ou Kerberos)
        # ------------------------------------------------------------------
        # WS-Trust enrollment primitives (--list-policies-ws / --enroll-ws)
        # talk HTTPS/443 to AD CS and authenticate via requests-gssapi, which
        # reads the system Kerberos cache directly (KRB5CCNAME). They do not
        # consume the CLI credential flags, so the validation chain below
        # must not reject them for lacking -u/-p/--hashes/-k. Add new
        # auth-less primitives to STANDALONE_PRIMITIVES as they appear.
        STANDALONE_PRIMITIVES = ("enroll_ws", "list_policies_ws")
        is_standalone = any(getattr(options, name, False) for name in STANDALONE_PRIMITIVES)

        if is_standalone:
            logging.debug(
                "Authentication skipped for standalone WS-Trust primitive "
                "(uses system Kerberos ccache via requests-gssapi)."
            )
            auth = None
        elif options.kerberos:
            # Mode Kerberos: on s'appuie sur le cache KRB5CCNAME.
            # Si le username est manquant, on l'extrait depuis le ccache.
            logging.debug('Authentication: Kerberos (KRB5CCNAME)')

            krb5cc = os.getenv('KRB5CCNAME')
            if not krb5cc:
                logging.warning("The KRB5CCNAME variable is not set. "
                                "Verify you have loaded a ticket (e.g. export KRB5CCNAME=/tmp/ticket.ccache).")
            elif not os.path.isfile(krb5cc):
                logging.warning("The ccache file pointed to by KRB5CCNAME was not found: %s", krb5cc)

            # If the user does not provide -u/-d, infer them from the ccache.
            if (not options.username) or (not options.domain):
                try:
                    from impacket.krb5.ccache import CCache
                    ccache_domain, ccache_user, _, _ = CCache.parseFile(
                        domain=options.domain or "",
                        username=options.username or "",
                        target=f"LDAP/{options.domain_controller}",
                    )
                    if not options.username and ccache_user:
                        options.username = ccache_user
                        logging.debug('Username extrait du ccache: %s', options.username)
                    if not options.domain and ccache_domain:
                        options.domain = ccache_domain
                        logging.debug('Domain extrait du ccache: %s', options.domain)
                except Exception as e:
                    logging.debug("Impossible de parser le ccache: %s", e)

            if not options.username:
                logging.critical("Username introuvable: passez -u ou utilisez un ccache contenant un principal valide.")
                sys.exit(1)
            if not options.domain:
                logging.critical("Domaine introuvable: passez -d ou utilisez un ccache contenant un principal valide.")
                sys.exit(1)

            auth = KerberosAuth(kdc_host=kdc_host)

        elif options.username is not None and options.password is not None:
            logging.debug('Authentication: username/password')
            auth = NTLMAuth(password=options.password)
        elif options.username is not None and options.password is None and options.hashes is None:
            options.password = getpass.getpass("Password:")
            logging.debug('Authentication: username/password')
            auth = NTLMAuth(password=options.password)
        elif options.hashes is not None and options.username is not None:
            logging.debug('Authentication: NT hash')
            if ':' in options.hashes:
                lm, nt = options.hashes.split(":")
            else:
                lm, nt = '', options.hashes
            auth = NTLMAuth(password=None, hashes=nt)
        else:
            logging.debug('Failed to parse options')
            logging.critical("No valid authentication method. Use -u/-p, --hashes, or -k.")
            sys.exit(1)

        print(banner)

        # MS-ADCAP CustomActions dispatch. These flags are mutually exclusive
        # (enforced by argparse) and short-circuit the whole collect pipeline: no
        # RootDSE, no Enumeration session, no cache, just one CustomActions SOAP
        # round-trip. Keeps the measurement signature small and separates the
        # MS-ADCAP primitives cleanly from the BloodHound collectors.
        #
        # Note the endpoint split: GetADForest and ChangeOptionalFeature target
        # the TopologyManagement capability, TranslateName targets the
        # AccountManagement capability (MS-ADCAP sections 3.2 vs 3.3).
        if getattr(options, "adcap_get_forest", False) \
                or getattr(options, "adcap_translate", None) \
                or getattr(options, "adcap_change_feature", None):
            # <ca:Server> header rejects an IP literal with 'Instance invalid';
            # resolve to an FQDN before opening any CustomActions client.
            dc_fqdn = _resolve_dc_fqdn(options.domain_controller)
            if getattr(options, "adcap_get_forest", False):
                tm_client = ADWSConnect.topology_cap_client(
                    dc_fqdn, options.domain, options.username, auth,
                )
                result = tm_client.get_ad_forest()
            elif getattr(options, "adcap_translate", None):
                am_client = ADWSConnect.account_cap_client(
                    dc_fqdn, options.domain, options.username, auth,
                )
                result = am_client.translate_name(options.adcap_translate)
            else:
                # Default DN for forest-level optional features (e.g. Recycle Bin):
                # CN=Partitions,CN=Configuration,<rootDN>. Overridable via
                # --adcap-change-feature-dn for feature-specific contexts.
                dn = getattr(options, "adcap_change_feature_dn", None)
                if not dn:
                    dn = "CN=Partitions,CN=Configuration," + ",".join(
                        f"DC={part}" for part in options.domain.split(".") if part
                    )
                tm_client = ADWSConnect.topology_cap_client(
                    dc_fqdn, options.domain, options.username, auth,
                )
                result = tm_client.change_optional_feature(dn, options.adcap_change_feature, enable=True)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            success = True
            return

        # WS-Trust certificate enrollment dispatch (MS-XCEP + MS-WSTEP).
        # Short-circuits the collect pipeline just like --adcap-* above: no
        # RootDSE, no Enumeration session, no cache. The two primitives
        # talk HTTPS/443 to /ADPolicyProvider_CEP_Kerberos and
        # /<ca>_CES_Kerberos/service.svc/CES, authenticating with the ccache
        # pointed to by KRB5CCNAME via requests-gssapi + RFC 5929 CBT.
        if getattr(options, "list_policies_ws", False):
            from soaphound.adcs.xcep import DEFAULT_USER_AGENT, run_list_policies

            run_list_policies(
                remote_name=options.domain_controller,
                cep_url=getattr(options, "cep_url", None),
                ca_name=getattr(options, "wstep_ca", None),
                insecure_ssl=getattr(options, "insecure_ssl", False),
                user_agent=getattr(options, "user_agent", None) or DEFAULT_USER_AGENT,
            )
            success = True
            return

        if getattr(options, "enroll_ws", False):
            from soaphound.adcs.wstep import run_enroll
            from soaphound.adcs.xcep import DEFAULT_USER_AGENT

            run_enroll(
                remote_name=options.domain_controller,
                ces_url=getattr(options, "ces_url", None),
                cep_url=getattr(options, "cep_url", None),
                ca_name=getattr(options, "wstep_ca", None),
                template_name=getattr(options, "wstep_template", None),
                upn=getattr(options, "wstep_upn", None),
                out_path=getattr(options, "wstep_out", None),
                insecure_ssl=getattr(options, "insecure_ssl", False),
                user_agent=getattr(options, "user_agent", None) or DEFAULT_USER_AGENT,
                auth_dc=getattr(options, "auth_dc", None),
            )
            success = True
            return

        # 1. RootDSE query (Resource)
        adws_resource = ADWSConnect(options.domain_controller, options.domain, options.username, auth, "Resource")
        contexts = adws_resource.get_rootdse_contexts(adws_resource._fqdn, adws_resource._nmf)
        schema_dn = contexts["schemaNamingContext"]
        default_dn = contexts["defaultNamingContext"]   # Use this DN for all pulls!
        root_domain_dn = contexts["rootDomainNamingContext"]
        config_dn = contexts["configurationNamingContext"]
        naming_contexts = contexts["namingContexts"]
        vals = contexts["domainFunctionality"]
        #Here we save domainFunctionality and ForestFunctionality value that we got from RootDSE request 
        domainFunctionality = int(vals[0]) if vals else None
        vals_forest = contexts["forestFunctionality"]
        forestFunctionality = int(vals[0]) if vals_forest else None

        # 2. One Enumeration connection for all pulls
        adws_enum = ADWSConnect(options.domain_controller, options.domain, options.username, auth, "Enumeration")

        if options.cert_find:
            force_epa = {"auto": None, "enabled": True, "disabled": False}.get(
                getattr(options, "cert_find_force_epa", "auto"), None
            )
            # NOTE: --cert-find keeps its existing multi-session model for now.
            # run_cert_find already receives adws_enum for its direct pulls, but its
            # internal helpers (build_directory_maps, collect_current_user_sids,
            # collect_certificate_templates, collect_certificate_authorities,
            # fetch_ca_security_descriptors_adws, ...) still call pull_all_ad_objects
            # with (ip, domain, username, auth) tuples, which opens one TCP:9389
            # session per helper. The shared-session refactor is scoped to the
            # BloodHound-equivalent collectors used by -c Default/Stealth below.
            run_cert_find(
                adws_enum=adws_enum,
                resource_client=adws_resource,
                config_dn=config_dn,
                schema_dn=schema_dn,
                default_dn=default_dn,
                domain=options.domain,
                username=options.username,
                auth=auth,
                output_dir=options.output_dir,
                web_probe_force_epa=force_epa,
                web_probe_enabled=not getattr(options, "cert_find_skip_web_probe", False),
                ca_rpc_enabled=not getattr(options, "cert_find_skip_ca_rpc", False),
            )
            success = True
            return

        # 3. ObjectType GUID Mapping (pass schema_dn)
        objecttype_guid_map = adws_objecttype_guid_map(adws_enum, schema_dn=schema_dn)
        objecttype_guid_map_normalized = {normalize_name(k): v for k, v in objecttype_guid_map.items()}
        laps_guid = objecttype_guid_map_normalized.get(normalize_name("ms-Mcs-AdmPwd"))
        laps2_guid = objecttype_guid_map_normalized.get(normalize_name("msLAPS-EncryptedPassword"))
        has_laps = laps_guid is not None
        has_laps2 = laps2_guid is not None

        main_query = "(|(objectCategory=person)(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount)(objectCategory=computer)(objectCategory=group)(objectClass=organizationalUnit)(objectClass=domain)(objectClass=container)(objectClass=groupPolicyContainer))"

        child_objects_query = "(|(objectClass=container)(objectClass=organizationalUnit)(sAMAccountType=805306369)(objectClass=group)(&(objectCategory=person)(objectClass=user)))"
        attributes_child = [ "objectSid", "objectClass", "objectGUID", "distinguishedName", "sAMAccountName", "sAMAccountType"]
        
        data_child_main = pull_all_ad_objects(
            adws_pull_client=adws_enum,
            ip=options.domain_controller, domain=options.domain, username=options.username, auth=auth,
            query=main_query, attributes=attributes_child, base_dn_override=default_dn
        )
        all_child_items = data_child_main.get("objects", [])

        # 4. Main collection (uses default_dn for base_dn)
        data_container_main = pull_all_ad_objects(
            adws_pull_client=adws_enum,
            ip=options.domain_controller, domain=options.domain, username=options.username, auth=auth,
            query=main_query, attributes=SOAPHOUND_CACHE_PROPERTIES, base_dn_override=default_dn
        )
        all_collected_items = data_container_main.get("objects", [])

        if not all_collected_items:
            logging.error("No objects collected (objs is empty or None)")
            sys.exit(1)

        objs = all_collected_items
        # Normalisation des objets si besoin
        if (isinstance(objs, list) and len(objs) == 1 and isinstance(objs[0], dict) and all(isinstance(v, list) for v in objs[0].values())):
            objs = fix_superdict_to_list(objs[0])
        elif isinstance(objs, dict) and all(isinstance(v, list) for v in objs.values()):
            objs = fix_superdict_to_list(objs)
        else:
            if not objs or not isinstance(objs, list) or not isinstance(objs[0], dict):
                logging.error("Something went wrong with object collected")
                sys.exit(1)

        for obj in objs:
            dn = obj.get('distinguishedName')
            if isinstance(dn, list):
                obj['distinguishedName'] = dn[0] if dn else ""
            oc = obj.get('objectClass')
            if isinstance(oc, str):
                obj['objectClass'] = [oc]
            elif oc is None:
                obj['objectClass'] = []

        # We Generate Soaphound Cache data
        create_and_combine_soaphound_cache(objs, default_dn, output_dir=options.output_dir)
        id_to_type_cache, value_to_id_cache = _generate_individual_caches(objs, default_dn)

        logging.info(f"Start collecting ...")

        
        
        # --- (1) Collect raw domains ---
        # Every ADWS collector below reuses the single `adws_enum` Enumeration
        # session created above (one TCP:9389 connection, one SPNEGO handshake).
        # The ip/domain/username/auth kwargs stay in the call for backward-compat
        # with standalone callers of each collector that do not share a client.
        raw_domains = collect_domains(adws_pull_client=adws_enum, ip=options.domain_controller, domain=options.domain, username=options.username, auth=auth)

        # Collect and format containers
        raw_containers = collect_containers(adws_pull_client=adws_enum, ip=options.domain_controller, domain=options.domain, username=options.username, auth=auth)
        containers_bh = format_containers(raw_containers, options.domain, default_dn, id_to_type_cache, value_to_id_cache, objs, objecttype_guid_map)

        # --- (2) Get main domain SID for formatting trusts etc. ---
        domain_obj = raw_domains[0]  # If only one domain, otherwise adapt according to the context.
        sid_bytes = domain_obj.get("objectSid")
            
        if isinstance(sid_bytes, bytes):
            domain_sid = LDAP_SID(sid_bytes).formatCanonical()
        elif isinstance(sid_bytes, str) and sid_bytes.upper().startswith("S-1-"):
            domain_sid = sid_bytes.upper()
        else:
            raise RuntimeError("Unable to find the SID of the primary domain.")

        collect_domain_args = {
        "username": options.username,
        "auth": auth
        }

        # Collect and format GPOs
        gpos = collect_gpos(adws_pull_client=adws_enum, ip=options.domain_controller, domain=options.domain, username=options.username, auth=auth)
        wmi_filters = collect_wmi_filters(adws_pull_client=adws_enum, ip=options.domain_controller, domain=options.domain, username=options.username, auth=auth, base_dn=default_dn)
        gpos_bh = format_gpos(gpos, options.domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map, wmi_filters=wmi_filters)


        # Collect and format Trusts
        trusts = collect_trusts(adws_pull_client=adws_enum, ip=options.domain_controller, domain=options.domain, username=options.username, auth=auth, domain_sid=domain_sid)
        

        
        print("Number of trusts collected:", len(trusts))

        # Trust audit report (if --trust-audit is set)
        # This performs a FOREST-WIDE trust enumeration: each domain in the forest
        # is queried for its TDOs, so both sides of each trust are analyzed. The BH
        # output above is unchanged - it still contains only the connected domain's
        # trusts, as expected by BloodHound.
        if getattr(options, 'trust_audit', False):
            try:
                forest_trusts = collect_forest_trusts(
                    adws_pull_client=adws_enum,
                    ip=options.domain_controller,
                    domain=options.domain,
                    username=options.username,
                    auth=auth,
                    naming_contexts=naming_contexts,
                    config_nc=config_dn,
                    schema_nc=schema_dn,
                    domain_sid=domain_sid,
                )
                if forest_trusts:
                    from soaphound.ad.trust_audit_report import generate_trust_audit_report
                    audit_trusts = [trust_to_audit_output(t) for t in forest_trusts]
                    # Preserve source domain tagging for the report
                    for at, ft in zip(audit_trusts, forest_trusts):
                        at['_source_domain_name'] = ft.get('source_domain_name', '')
                        at['_source_domain_dn'] = ft.get('source_domain_dn', '')
                    report_path = generate_trust_audit_report(
                        audit_trusts,
                        domain_name=options.domain,
                        output_dir=options.output_dir,
                        prefix=getattr(options, 'outputprefix', None),
                    )
                    print(f"[+] Trust audit report saved: {report_path}")
                else:
                    print("[!] No trusts found in the forest; audit report skipped")
            except Exception as _e:
                import traceback
                print(f"[!] Trust audit report generation failed: {_e}")
                traceback.print_exc()

        # --- (3b) Optional SYSVOL collection for GPOChanges ---
        gpo_changes = None
        gpp_passwords = []
        privilege_rights = {}
        _gpo_guids_with_changes = set()
        if should_skip_sysvol(options):
            logging.info(
                "[!] Stealth mode: skipping SYSVOL collection (TCP:445). "
                "GPO settings, local admins and GPP cpassword will not be in the output."
            )
            sysvol_conn = None
        else:
            sysvol_conn = connect_sysvol(options.domain_controller, options.domain, options.username, auth)
        if sysvol_conn:
            try:
                import re as _re
                _guid_pat = _re.compile(r'\{([A-F0-9\-]{36})\}', _re.IGNORECASE)
                gpo_guids = []
                for g in gpos_bh.get("data", []):
                    gpcpath = (g.get("Properties") or {}).get("gpcpath") or ""
                    m = _guid_pat.search(gpcpath)
                    if m:
                        gpo_guids.append(m.group(1))
                gpo_changes, gpp_passwords, privilege_rights, _gpo_guids_with_changes = collect_gpo_sysvol_changes(
                    sysvol_conn, options.domain, gpo_guids,
                    id_to_type_cache, value_to_id_cache
                )
                if gpp_passwords:
                    logging.warning("[!] GPP passwords found (%d) — saved to gpp_passwords.json", len(gpp_passwords))
            except Exception as _exc:
                logging.warning("SYSVOL GPOChanges collection failed: %s", _exc)
            finally:
                try:
                    sysvol_conn.logoff()
                except Exception:
                    pass
        else:
            logging.info("SYSVOL unreachable — GPOChanges will be empty")

        # --- (4) Format domains, inject trusts ---
        domains_bh = format_domains(
        raw_domains, options.domain, default_dn,
        id_to_type_cache, value_to_id_cache,
        all_child_items,
        objecttype_guid_map, trusts,
        domain_functionality=domainFunctionality,
        gpo_changes=gpo_changes
    )


     
        # Collect and format OUs
        ous = collect_ous(adws_pull_client=adws_enum, ip=options.domain_controller, domain=options.domain, username=options.username, auth=auth)
        ous_bh = format_ous(ous, options.domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map)

        # Collect and format Groups
        groups = collect_groups(adws_pull_client=adws_enum, ip=options.domain_controller, domain=options.domain, username=options.username, auth=auth)
        groups_bh = format_groups(groups, options.domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map)

        # Collect and format Users
        object_classes = adws_object_classes(adws_enum)
        users = collect_users(adws_pull_client=adws_enum, ip=options.domain_controller, domain=options.domain, username=options.username, auth=auth, adws_object_classes=object_classes,adws_objecttype_guid_map=objecttype_guid_map)
        users_bh = format_users(users, options.domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map)


        # Collect and format Computers
        # Stealth skips the SMB/RPC session enumeration path. ADWSOnly is
        # remapped to Stealth above, so it never reaches this check.
        if (options.collectionmethod == "Stealth"):
            computers = collect_computers_adws(
                adws_pull_client=adws_enum,
                ip=options.domain_controller, domain=options.domain, username=options.username, auth=auth,
                base_dn_override=default_dn, adws_object_classes=object_classes,
                has_laps=has_laps, has_lapsv2=has_laps2,objecttype_guid_map=objecttype_guid_map )
            
            computers_bh = format_computers_adws(computers, options.domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map=objecttype_guid_map)
        else:
            # ------------------------------------------------------------------
            # Configuration de l'authentification SMB/RPC (collecte de sessions)
            # ------------------------------------------------------------------
            if options.kerberos:
                # En mode Kerberos, on charge le ticket depuis le ccache (KRB5CCNAME)
                # afin que les connexions SMB/RPC utilisent ce TGT.
                smb_auth = ADAuthentication(
                    username=options.username,
                    password='',
                    domain=options.domain,
                    lm_hash='',
                    nt_hash='',
                    aeskey=aeskey,
                    kdc=kdc_host,
                    auth_method='kerberos',
                )
                try:
                    if not smb_auth.load_ccache():
                        logging.warning("Impossible de charger un TGT depuis le ccache. "
                                        "SMB session collection may fail. "
                                        "Verify KRB5CCNAME and the ticket validity.")
                except Exception as e:
                    logging.warning("Erreur lors du chargement du ccache: %s", e)
            else:
                smb_auth = ADAuthentication(username=options.username, password=options.password, domain=options.domain, lm_hash=lm, nt_hash=nt, aeskey=aeskey, kdc=options.domain_controller)

            addomain = ADDomain(
                name=options.domain,
                netbios_name=None,
                sid=domain_sid,
                distinguishedname=default_dn
            )
            addomain.domain = addomain.name
            addomain.auth = smb_auth
            addomain.dnscache = DNSCache()
            addomain.dnsresolver = dns.resolver.Resolver()
            addomain.dns_tcp = dns.resolver.Resolver(); addomain.dns_tcp.use_tcp = True
            addomain.sidcache = ObjectCache()
            addomain.samcache = ObjectCache()
            addomain.computersidcache = ObjectCache()
            addomain.num_domains = 1

            # Build SID -> {sam, domain} cache from the already-collected users,
            # groups, and computer accounts. Used by ADComputer._format_sid_friendly
            # to display readable session principals (DOMAIN\\sam) instead of raw
            # SIDs during NetSessionEnum / RegistryUsers enumeration.
            try:
                netbios_label = options.domain.split(".")[0].upper() if options.domain else "DOMAIN"
                sid_cache = {}
                for collection_bh in (users_bh, groups_bh):
                    # Handle both list format and BH dict format {"data": [...], "meta": {...}}
                    if isinstance(collection_bh, dict):
                        items = collection_bh.get("data") or []
                    else:
                        items = collection_bh or []
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        sid = item.get("ObjectIdentifier") or (item.get("Properties") or {}).get("objectsid")
                        props = item.get("Properties") or {}
                        sam = props.get("samaccountname")
                        if sid and sam:
                            sid_cache[sid] = {"sam": sam, "domain": netbios_label}
                addomain.sid_to_sam_cache = sid_cache
                logging.debug("Built sid_to_sam_cache with %d entries (NETBIOS=%s)",
                              len(sid_cache), netbios_label)
            except Exception as _e:
                logging.warning("Could not build sid_to_sam_cache: %s -- session SIDs will display raw", _e)
                addomain.sid_to_sam_cache = {}

            def get_domain_by_name(name):
                if name.lower() == addomain.name.lower():
                    return addomain
                return None
            addomain.get_domain_by_name = get_domain_by_name

            computers = collect_computers(
                adws_pull_client=adws_enum,
                ip=options.domain_controller, domain=options.domain, username=options.username, auth=auth,
                base_dn_override=default_dn, adws_object_classes=object_classes,
                has_laps=has_laps, has_lapsv2=has_laps2, objecttype_guid_map=objecttype_guid_map
            )
            computers_bh = format_computers(
                computers, options.domain, domain_sid, adws_enum,
                id_to_type_cache, value_to_id_cache, objecttype_guid_map,
                bh_rpc_context=addomain, num_workers=options.worker_num
            )

        # --- AffectedComputers: resolve computers in OUs linked to GPOs with changes ---
        if gpo_changes is not None and _gpo_guids_with_changes:
            try:
                affected = compute_affected_computers(
                    _gpo_guids_with_changes, ous, computers, id_to_type_cache
                )
                gpo_changes["AffectedComputers"] = affected
                for d in domains_bh.get("data", []):
                    d["GPOChanges"]["AffectedComputers"] = affected
            except Exception as _exc:
                logging.warning("compute_affected_computers failed: %s", _exc)

        timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S') + "_"
        output_dir = options.output_dir
        safe_export_bloodhound_json(domains_bh, os.path.join(output_dir, timestamp + "domains.json"))
        safe_export_bloodhound_json(containers_bh, os.path.join(output_dir, timestamp + "containers.json"))
        safe_export_bloodhound_json(gpos_bh, os.path.join(output_dir, timestamp + "gpos.json"))
        safe_export_bloodhound_json(ous_bh, os.path.join(output_dir, timestamp + "ous.json"))
        safe_export_bloodhound_json(groups_bh, os.path.join(output_dir, timestamp + "groups.json"))
        safe_export_bloodhound_json(users_bh, os.path.join(output_dir, timestamp + "users.json"))
        safe_export_bloodhound_json(computers_bh, os.path.join(output_dir, timestamp + "computers.json"))

        if gpp_passwords:
            gpp_path = os.path.join(output_dir, timestamp + "gpp_passwords.json")
            export_bloodhound_json({"count": len(gpp_passwords), "data": gpp_passwords}, gpp_path)
            print(f"[!] GPP passwords saved: {gpp_path}")

        if privilege_rights:
            pr_path = os.path.join(output_dir, timestamp + "privilege_rights.json")
            export_bloodhound_json({"domain": options.domain, "data": privilege_rights}, pr_path)
            print(f"[+] Privilege rights saved: {pr_path}")

        if options.zip:
            zip_bloodhound_jsons(output_dir, timestamp, timestamp + "bloodhound.zip")

        success = True
    finally:
        elapsed = _format_duration(time.monotonic() - start)
        if success:
            print(f"[+] Collection completed in {elapsed}")
        else:
            print(f"[-] Collection aborted after {elapsed}")


if __name__ == "__main__":
    main()
