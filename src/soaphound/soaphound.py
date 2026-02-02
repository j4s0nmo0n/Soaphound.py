import logging, sys, os, getpass, json, dns.resolver, datetime, time, zipfile, base64
from soaphound.lib.cli import gen_cli_args
from impacket.ldap.ldaptypes import LDAP_SID
from soaphound.ad.adws import ADWSConnect, NTLMAuth
from soaphound.ad.cache_gen import (
    pull_all_ad_objects, adws_objecttype_guid_map, generate_caches,
    _generate_individual_caches, adws_object_classes, create_and_combine_soaphound_cache,
    SOAPHOUND_LDAP_PROPERTIES, SOAPHOUND_CACHE_PROPERTIES
)
from soaphound.ad.acls import normalize_name

from soaphound.ad.collectors.domain import collect_domains, format_domains
from soaphound.ad.collectors.container import collect_containers, format_containers
from soaphound.ad.collectors.gpo import collect_gpos, format_gpos
from soaphound.ad.collectors.ou import collect_ous, format_ous
from soaphound.ad.collectors.group import collect_groups, format_groups
from soaphound.ad.collectors.user import collect_users, format_users
from soaphound.ad.collectors.trust import collect_trusts, trust_to_bh_output

from soaphound.lib.utils import ObjectCache, DNSCache
from soaphound.lib.authentication import ADAuthentication
from soaphound.ad.collectors.computer import collect_computers, format_computers
from soaphound.ad.collectors.computer_adws import collect_computers_adws, format_computers_adws
from soaphound.lib.domain import ADDomain

def export_bloodhound_json(data, output_path):
    """Export data to BloodHound JSON file"""
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(clean_bytes(data), f, indent=2)

def safe_export_bloodhound_json(data, output_path):
    """Export only if data contains objects"""
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

def zip_bloodhound_jsons(output_dir, timestamp, archive_name="BloodHound.zip"):
    """
    Archive all .json files from output_dir to BloodHound.zip,
    excluding cache files (case insensitive).
    """
    archive_path = archive_name
    with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as archive:
        for fname in os.listdir(output_dir):
            if fname.lower().endswith(".json") and fname.lower().startswith(timestamp):
                fpath = os.path.join(output_dir, fname)
                archive.write(fpath, arcname=fname)
    print(f"Zip file created at: {archive_path}")

def ensure_output_dir(output_dir):
    """
    Ensure output directory is valid and exists.
    
    Args:
        output_dir: Directory path (can be empty or None)
        
    Returns:
        str: Valid directory path
    """
    # Default value if empty
    if not output_dir or output_dir.strip() == '':
        output_dir = 'output'
        logging.info(f"Using default output directory: {output_dir}")
    
    # Clean the path
    output_dir = output_dir.strip()
    
    # Create if doesn't exist
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
            logging.debug(f"Created output directory: {output_dir}")
        except OSError as e:
            logging.error(f"Failed to create output directory '{output_dir}': {e}")
            raise
    
    return output_dir

def main():
    options = gen_cli_args()
    
    # Validate and create output directory early
    options.output_dir = ensure_output_dir(options.output_dir)
    
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
    
    # Configure logging based on verbosity level
    log_format = '%(asctime)s %(levelname)s: %(name)s: %(message)s' if options.ts else '[%(levelname)s] %(message)s'

    logger = logging.getLogger()
    
    logger.handlers.clear()
    # Determine log level
    if options.v:
        log_level = logging.DEBUG
        # In debug mode, add file handler
        log_file = f"soaphound_debug_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s:%(funcName)s:%(lineno)d - %(message)s'
        ))
        logger.addHandler(file_handler)
        logging.info(f"Debug log will be written to: {log_file}")
    else:
        log_level = logging.INFO

    logger.setLevel(log_level)
    
    # Console handler
    stream = logging.StreamHandler(sys.stderr)
    stream.setLevel(log_level)
    formatter = logging.Formatter(log_format)
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    logging.debug(f"Options: {options}")

    lm = ''
    nt = ''
    
    # Parse authentication options
    if options.username is not None and options.password is not None:
        logging.debug('Authentication: username/password')
        auth = NTLMAuth(password=options.password)
    elif options.username is not None and options.password is None and options.hashes is None:
        options.password = getpass.getpass("Password:")
        logging.debug('Authentication: username/password')
        auth = NTLMAuth(password=options.password)
    elif options.hashes is not None and options.username is not None:
        logging.debug('Authentication: NT hash')
        lm, nt = options.hashes.split(":")
        auth = NTLMAuth(password=None, hashes=nt)
    else:
        logging.error('Failed to parse authentication options')
        sys.exit(1)

    print(banner)

    # 1. RootDSE query (Resource endpoint)
    logging.info("Connecting to ADWS Resource endpoint...")
    adws_resource = ADWSConnect(options.domain_controller, options.domain, options.username, auth, "Resource")
    contexts = adws_resource.get_rootdse_contexts(adws_resource._fqdn, adws_resource._nmf)
    
    schema_dn = contexts["schemaNamingContext"]
    default_dn = contexts["defaultNamingContext"]  # Use this DN for all pulls!
    root_domain_dn = contexts["rootDomainNamingContext"]
    config_dn = contexts["configurationNamingContext"]
    naming_contexts = contexts["namingContexts"]
    
    # Save domainFunctionality and forestFunctionality values from RootDSE request
    vals = contexts["domainFunctionality"]
    domainFunctionality = int(vals[0]) if vals else None
    vals_forest = contexts["forestFunctionality"]
    forestFunctionality = int(vals_forest[0]) if vals_forest else None

    logging.info(f"Connected to domain: {options.domain}")
    logging.info(f"Default naming context: {default_dn}")

    # 2. One Enumeration connection for all pulls
    logging.info("Connecting to ADWS Enumeration endpoint...")
    adws_enum = ADWSConnect(options.domain_controller, options.domain, options.username, auth, "Enumeration")

    # 3. ObjectType GUID Mapping (pass schema_dn)
    logging.info("Retrieving schema ObjectType GUID mappings...")
    objecttype_guid_map = adws_objecttype_guid_map(adws_enum, schema_dn=schema_dn, follow_referrals=options.follow_referrals)
    objecttype_guid_map_normalized = {normalize_name(k): v for k, v in objecttype_guid_map.items()}
    
    # Check for LAPS support
    laps_guid = objecttype_guid_map_normalized.get(normalize_name("ms-Mcs-AdmPwd"))
    laps2_guid = objecttype_guid_map_normalized.get(normalize_name("msLAPS-EncryptedPassword"))
    has_laps = laps_guid is not None
    has_laps2 = laps2_guid is not None
    
    if has_laps:
        logging.info("LAPS v1 detected in schema")
    if has_laps2:
        logging.info("LAPS v2 detected in schema")

    # 4. Main collection query for cache generation
    logging.info("Collecting objects for cache generation...")
    main_query = "(|(objectCategory=person)(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount)(objectCategory=computer)(objectCategory=group)(objectClass=organizationalUnit)(objectClass=domain)(objectClass=container)(objectClass=groupPolicyContainer))"

    # Child objects for containment relationships
    child_objects_query = "(|(objectClass=container)(objectClass=organizationalUnit)(sAMAccountType=805306369)(objectClass=group)(&(objectCategory=person)(objectClass=user)))"
    attributes_child = ["objectSid", "objectClass", "objectGUID", "distinguishedName", "sAMAccountName", "sAMAccountType"]
    
    data_child_main = pull_all_ad_objects(
        ip=options.domain_controller, domain=options.domain, username=options.username, auth=auth,
        query=main_query, attributes=attributes_child, base_dn_override=default_dn
    )
    all_child_items = data_child_main.get("objects", [])
    
    # Main collection (use default_dn for base_dn)
    data_container_main = pull_all_ad_objects(
        ip=options.domain_controller, domain=options.domain, username=options.username, auth=auth,
        query=main_query, attributes=SOAPHOUND_CACHE_PROPERTIES, base_dn_override=default_dn
    )
    all_collected_items = data_container_main.get("objects", [])

    if not all_collected_items:
        logging.error("No objects collected (collection is empty or None)")
        sys.exit(1)

    objs = all_collected_items
    
    # Normalize objects
    for obj in objs:
        dn = obj.get('distinguishedName')
        if isinstance(dn, list):
            obj['distinguishedName'] = dn[0] if dn else ""
        oc = obj.get('objectClass')
        if isinstance(oc, str):
            obj['objectClass'] = [oc]
        elif oc is None:
            obj['objectClass'] = []

    # Generate SOAPHound Cache data with domain name in filename
    logging.info("Generating SOAPHound cache...")
    create_and_combine_soaphound_cache(
        objs, 
        default_dn, 
        output_dir=options.output_dir,
        domain_name=options.domain
    )
    id_to_type_cache, value_to_id_cache = _generate_individual_caches(objs, default_dn)

    logging.info("Starting collection of AD objects...")

    # --- Collect raw domains ---
    logging.info("Collecting domains...")
    raw_domains = collect_domains(options.domain_controller, options.domain, options.username, auth)
    
    # Collect and format containers
    logging.info("Collecting containers...")
    raw_containers = collect_containers(options.domain_controller, options.domain, options.username, auth)
    containers_bh = format_containers(
        raw_containers, options.domain, default_dn, 
        id_to_type_cache, value_to_id_cache, objs, objecttype_guid_map
    )

    # Get main domain SID for formatting trusts etc.
    domain_obj = raw_domains[0]  # If only one domain
    sid_bytes = domain_obj.get("objectSid")
        
    if isinstance(sid_bytes, bytes):
        domain_sid = LDAP_SID(sid_bytes).formatCanonical()
    elif isinstance(sid_bytes, str) and sid_bytes.upper().startswith("S-1-"):
        domain_sid = sid_bytes.upper()
    else:
        raise RuntimeError("Unable to find the SID of the primary domain.")

    logging.info(f"Domain SID: {domain_sid}")

    # Collect and format GPOs
    logging.info("Collecting GPOs...")
    gpos = collect_gpos(options.domain_controller, options.domain, options.username, auth)
    gpos_bh = format_gpos(
        gpos, options.domain, domain_sid, 
        id_to_type_cache, value_to_id_cache, objecttype_guid_map
    )

    # Collect and format Trusts
    logging.info("Collecting trusts...")
    trusts = collect_trusts(
        options.domain_controller, options.domain, options.username, auth, 
        domain_sid=domain_sid
    )
    logging.info(f"Trusts collected: {len(trusts)}")
    
    # Format domains with trusts
    domains_bh = format_domains(
        raw_domains, options.domain, default_dn,
        id_to_type_cache, value_to_id_cache,
        all_child_items,   
        objecttype_guid_map, trusts,
        domain_functionality=domainFunctionality
    )

    # Collect and format OUs
    logging.info("Collecting OUs...")
    ous = collect_ous(options.domain_controller, options.domain, options.username, auth)
    ous_bh = format_ous(
        ous, options.domain, domain_sid, 
        id_to_type_cache, value_to_id_cache, objecttype_guid_map
    )

    # Collect and format Groups
    logging.info("Collecting groups...")
    groups = collect_groups(options.domain_controller, options.domain, options.username, auth)
    groups_bh = format_groups(
        groups, options.domain, domain_sid, 
        id_to_type_cache, value_to_id_cache, objecttype_guid_map
    )

    # Collect and format Users
    logging.info("Collecting users...")
    object_classes = adws_object_classes(adws_enum)
    users = collect_users(
        options.domain_controller, options.domain, options.username, auth, 
        adws_object_classes=object_classes, adws_objecttype_guid_map=objecttype_guid_map
    )
    users_bh = format_users(
        users, options.domain, domain_sid, 
        id_to_type_cache, value_to_id_cache, objecttype_guid_map
    )

    # Collect and format Computers
    logging.info("Collecting computers...")
    if options.collectionmethod == "ADWSOnly":
        computers = collect_computers_adws(
            options.domain_controller, options.domain, options.username, auth,
            base_dn_override=default_dn, adws_object_classes=object_classes,
            has_laps=has_laps, has_lapsv2=has_laps2, objecttype_guid_map=objecttype_guid_map
        )
        
        computers_bh = format_computers_adws(
            computers, options.domain, domain_sid, 
            id_to_type_cache, value_to_id_cache, objecttype_guid_map=objecttype_guid_map
        )
    else:
        # Full collection with RPC/SMB sessions
        smb_auth = ADAuthentication(
            username=options.username, password=options.password, domain=options.domain, 
            lm_hash=lm, nt_hash=nt, aeskey='', kdc=options.domain_controller
        )
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
        addomain.dns_tcp = dns.resolver.Resolver()
        addomain.dns_tcp.use_tcp = True
        addomain.sidcache = ObjectCache()
        addomain.samcache = ObjectCache()
        addomain.computersidcache = ObjectCache()
        addomain.num_domains = 1

        def get_domain_by_name(name):
            if name.lower() == addomain.name.lower():
                return addomain
            return None
        addomain.get_domain_by_name = get_domain_by_name

        computers = collect_computers(
            options.domain_controller, options.domain, options.username, auth,
            base_dn_override=default_dn, adws_object_classes=object_classes,
            has_laps=has_laps, has_lapsv2=has_laps2, objecttype_guid_map=objecttype_guid_map
        )
        computers_bh = format_computers(
            computers, options.domain, domain_sid, adws_enum,
            id_to_type_cache, value_to_id_cache, objecttype_guid_map,
            bh_rpc_context=addomain, num_workers=options.worker_num
        )

    # Generate timestamp for output files
    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S') + "_"
    output_dir = options.output_dir
    
    # Export all collections to JSON
    logging.info("Exporting BloodHound JSON files...")
    safe_export_bloodhound_json(domains_bh, os.path.join(output_dir, timestamp + "domains.json"))
    safe_export_bloodhound_json(containers_bh, os.path.join(output_dir, timestamp + "containers.json"))
    safe_export_bloodhound_json(gpos_bh, os.path.join(output_dir, timestamp + "gpos.json"))
    safe_export_bloodhound_json(ous_bh, os.path.join(output_dir, timestamp + "ous.json"))
    safe_export_bloodhound_json(groups_bh, os.path.join(output_dir, timestamp + "groups.json"))
    safe_export_bloodhound_json(users_bh, os.path.join(output_dir, timestamp + "users.json"))
    safe_export_bloodhound_json(computers_bh, os.path.join(output_dir, timestamp + "computers.json"))

    # Summary statistics
    logging.info("=" * 60)
    logging.info("COLLECTION SUMMARY")
    logging.info("=" * 60)
    logging.info(f"Domains:    {domains_bh['meta']['count']}")
    logging.info(f"Containers: {containers_bh['meta']['count']}")
    logging.info(f"GPOs:       {gpos_bh['meta']['count']}")
    logging.info(f"OUs:        {ous_bh['meta']['count']}")
    logging.info(f"Groups:     {groups_bh['meta']['count']}")
    logging.info(f"Users:      {users_bh['meta']['count']}")
    logging.info(f"Computers:  {computers_bh['meta']['count']}")
    logging.info("=" * 60)

    # Create ZIP archive if requested
    if options.zip:
        logging.info("Creating ZIP archive...")
        zip_bloodhound_jsons(output_dir, timestamp, timestamp + "bloodhound.zip")

    logging.info("Collection completed successfully!")

if __name__ == "__main__":
    main()
