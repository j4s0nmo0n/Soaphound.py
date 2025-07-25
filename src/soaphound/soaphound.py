import logging, sys, os, getpass, json, dns.resolver, datetime, time, zipfile
from soaphound.lib.cli import gen_cli_args
from impacket.ldap.ldaptypes import LDAP_SID
from impacket.examples.utils import parse_target
from soaphound.ad.adws import ADWSConnect, NTLMAuth
from soaphound.ad.cache_gen import pull_all_ad_objects, adws_objecttype_guid_map, generate_caches, _generate_individual_caches, adws_object_classes, create_and_combine_soaphound_cache, SOAPHOUND_LDAP_PROPERTIES 
from soaphound.ad.acls import normalize_name

from soaphound.ad.collectors.domain import collect_domains, format_domains
from soaphound.ad.collectors.container import collect_containers, format_containers
from soaphound.ad.collectors.gpo import collect_gpos, format_gpos
from soaphound.ad.collectors.ou import collect_ous, format_ous
from soaphound.ad.collectors.group import collect_groups, format_groups
from soaphound.ad.collectors.user import collect_users, format_users
from soaphound.ad.collectors.trust import collect_trusts, format_trusts

from soaphound.lib.utils import ObjectCache, DNSCache
from soaphound.lib.authentication import ADAuthentication
from soaphound.ad.collectors.computer import collect_computers, format_computers
from soaphound.ad.collectors.computer_adws import collect_computers_adws, format_computers_adws
from soaphound.lib.domain import ADDomain


def export_bloodhound_json(data, output_path):
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(clean_bytes(data), f, indent=2)
        #json.dump(data, f, indent=2)

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
    sauf cache.json (insensible à la casse).
    """
    archive_path = archive_name
    with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as archive:
        for fname in os.listdir(output_dir):
            if fname.lower().endswith(".json") and fname.lower().startswith(timestamp):
                fpath = os.path.join(output_dir, fname)
                archive.write(fpath, arcname=fname)
    print(f"Zip file created at : {archive_path}")

def main():

    options = gen_cli_args()
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
                                                                                                    (made by BeletteTimoree)
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

    lm = ''
    nt = ''
    
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
        logging.debug('Failed to parse options')
        parser.print_help()
        sys.exit(1)


    print(banner)

    main_query = "(|(objectCategory=person)(objectClass=msDS-GroupManagedServiceAccount) (objectClass=msDS-ManagedServiceAccount)(objectCategory=computer)(objectCategory=group)(objectClass=organizationalUnit)(objectClass=domain)(objectClass=container)(objectClass=groupPolicyContainer))"
    main_domain_root_dn = "DC=" + ",DC=".join(options.domain.split('.'))
    

    logging.info(f"Trying to connect to {options.domain_controller} ...")
    adws_conn = ADWSConnect(options.domain_controller, options.domain, options.username, auth, "Enumeration") 

    objecttype_guid_map = adws_objecttype_guid_map(adws_conn)
    objecttype_guid_map_normalized = {normalize_name(k): v for k, v in objecttype_guid_map.items()}
    laps_guid = objecttype_guid_map_normalized.get(normalize_name(("ms-Mcs-AdmPwd")))
    laps2_guid = objecttype_guid_map_normalized.get(normalize_name(("msLAPS-EncryptedPassword")))
    has_laps = laps_guid is not None
    has_laps2 = laps2_guid is not None
    data_container_main = pull_all_ad_objects(ip=options.domain_controller, domain=options.domain, username=options.username, auth=auth, query=main_query, attributes=SOAPHOUND_LDAP_PROPERTIES)

    all_collected_items = data_container_main.get("objects", [])

    # Generate the SOAPHound cache right now (this is useful for everything else later)

    value_to_id_cache, id_to_type_cache = generate_caches(all_collected_items)

    objs = all_collected_items
    if not objs:
        logging.error("No objects collected (objs is empty or None)")
        sys.exit(1)

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


    create_and_combine_soaphound_cache(objs, main_domain_root_dn, output_dir=options.output_dir)
    
    # Generate in-memory caches (for use in the following steps)
    id_to_type_cache, value_to_id_cache = _generate_individual_caches(objs, main_domain_root_dn)


    logging.info(f"Start collecting ...")
    # Collect and format domains    
    raw_domains = collect_domains(options.domain_controller, options.domain, options.username, auth)
    domains_bh = format_domains(raw_domains, options.domain, main_domain_root_dn, id_to_type_cache, value_to_id_cache, objs, objecttype_guid_map)

    # Collect and format containers
    raw_containers = collect_containers(options.domain_controller, options.domain, options.username, auth)
    containers_bh = format_containers(raw_containers, options.domain, main_domain_root_dn, id_to_type_cache, value_to_id_cache, objs, objecttype_guid_map)

    domain_obj = raw_domains[0]  # If only one domain, otherwise adapt according to the context.
    sid_bytes = domain_obj.get("objectSid")
        
    if isinstance(sid_bytes, bytes):
        domain_sid = LDAP_SID(sid_bytes).formatCanonical()
    elif isinstance(sid_bytes, str) and sid_bytes.upper().startswith("S-1-"):
        domain_sid = sid_bytes.upper()
    else:
        raise RuntimeError("Unable to find the SID of the primary domain.")

    # Collect and format GPOs
    gpos = collect_gpos(options.domain_controller, options.domain, options.username, auth)
    gpos_bh = format_gpos(gpos, options.domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map)
        
    # Collect and format OUs
    ous = collect_ous(options.domain_controller, options.domain, options.username, auth)
    ous_bh = format_ous(ous, options.domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map)

    # Collect and format Groups
    groups = collect_groups(options.domain_controller, options.domain, options.username, auth)
    groups_bh = format_groups(groups, options.domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map)

    # Collect and format Users
    object_classes = adws_object_classes(adws_conn)
    users = collect_users(options.domain_controller, options.domain, options.username, auth, adws_object_classes=object_classes)
    users_bh = format_users(users, options.domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map)

    # Collect and format Trusts
    trusts = collect_trusts(options.domain_controller, options.domain, options.username, auth)
    trusts_bh = format_trusts(trusts, options.domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map)

    # Collect and format Computers
    if (options.collectionmethod == "ADWSOnly"):
        computers = collect_computers_adws(options.domain_controller, options.domain, options.username, auth, base_dn_override=None, adws_object_classes=object_classes, has_laps=has_laps, has_lapsv2=has_laps2)
        computers_bh = format_computers_adws(computers, options.domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map)
    else:
        smb_auth = ADAuthentication(username=options.username, password=options.password, domain=options.domain, lm_hash=lm, nt_hash=nt,aeskey='',kdc=options.domain_controller)
        addomain = ADDomain(
            name=options.domain,                         # ex: 'JJK.LOCAL' ..and by the way Gojo is stronger than Sukuna
            netbios_name=None,           # Retrieved from collect_domains, or None if unknown.
            sid=domain_sid,                      # ex: 'S-1-5-21-...'
            distinguishedname=main_domain_root_dn  # ex: 'DC=JJK,DC=LOCAL'
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

        def get_domain_by_name(name):
            if name.lower() == addomain.name.lower():
                return addomain
            return None
        addomain.get_domain_by_name = get_domain_by_name

        computers = collect_computers(options.domain_controller, options.domain, options.username, auth, base_dn_override=None, adws_object_classes=object_classes, has_laps=has_laps, has_lapsv2=has_laps2)
        computers_bh = format_computers(computers, options.domain, domain_sid, adws_conn, id_to_type_cache, value_to_id_cache, objecttype_guid_map, bh_rpc_context=addomain, num_workers=options.worker_num)



    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S') + "_"

    output_dir = options.output_dir
    safe_export_bloodhound_json(domains_bh, os.path.join(output_dir, timestamp + "domains.json"))
    safe_export_bloodhound_json(containers_bh, os.path.join(output_dir, timestamp + "containers.json"))
    safe_export_bloodhound_json(gpos_bh, os.path.join(output_dir, timestamp + "gpos.json"))
    safe_export_bloodhound_json(ous_bh, os.path.join(output_dir, timestamp + "ous.json"))
    safe_export_bloodhound_json(groups_bh, os.path.join(output_dir, timestamp + "groups.json"))
    safe_export_bloodhound_json(users_bh, os.path.join(output_dir, timestamp + "users.json"))
    safe_export_bloodhound_json(trusts_bh, os.path.join(output_dir, timestamp + "trusts.json"))
    safe_export_bloodhound_json(computers_bh, os.path.join(output_dir, timestamp + "computers.json"))

    if options.zip:
        zip_bloodhound_jsons(output_dir, timestamp, timestamp + "bloodhound.zip")

if __name__ == "__main__":
    main()
