from uuid import UUID
import logging
from impacket.ldap.ldaptypes import LDAP_SID

from soaphound.ad.cache_gen import pull_all_ad_objects, _ldap_datetime_to_epoch, _parse_aces, dedupe_aces,adws_objecttype_guid_map
from soaphound.ad.adws import WELL_KNOWN_SIDS
from .container import get_child_objects, BH_TYPE_LABEL_MAP

def collect_domains(ip, domain, username, auth, base_dn_override=None):
    """
    Collecte les objets de type 'domain' (domainDNS uniquement)
    """
    attributes = [
        "name", "objectGUID", "objectSid", "objectClass", "distinguishedName",
        "nTSecurityDescriptor", "whenCreated", "cn"
    ]
    domains = pull_all_ad_objects(
        ip=ip,
        domain=domain,
        username=username,
        auth=auth,
        query="(objectClass=domainDNS)",
        attributes=attributes,
        base_dn_override=base_dn_override
    ).get("objects", [])
    print(f"[INFO] Domains collected : {len(domains)}")
    return domains

    

def prefix_well_known_sid(sid: str, domain_name: str, domain_sid: str, well_known_sids=WELL_KNOWN_SIDS):
    sid = sid.upper()
    domain_sid = domain_sid.upper()
    if sid.startswith(domain_sid + "-") or sid == domain_sid:
        return sid
    # Ajoute le préfixe si S-1-5-32-XXX ou dans la table well known
    if sid in well_known_sids or sid.startswith("S-1-5-32-"):
        return f"{domain_name.upper()}-{sid}"
    return sid

def format_domains(domains, domain_name, domain_root_dn, id_to_type_cache, value_to_id_cache, all_collected_items, objecttype_guid_map):
    # Construction du lookup DN parent -> enfants directs (containers, OUs, etc)
    childobjects_lookup = {}
    for obj in all_collected_items:
        dn_child = obj.get("distinguishedName")
        guid_child = obj.get("objectGUID")
        obj_classes = obj.get("objectClass", [])
        obj_type = obj_classes[0] if isinstance(obj_classes, list) and obj_classes else obj_classes or "Unknown"
        parent_dn = None
        if dn_child and ',' in dn_child:
            parent_dn = dn_child.split(",", 1)[1]
        if parent_dn:
            childobjects_lookup.setdefault(parent_dn.upper(), []).append({
                "ObjectIdentifier": str(UUID(bytes_le=guid_child)) if isinstance(guid_child, bytes) else guid_child,
                "ObjectType": obj_type.title() if obj_type else "Unknown",
            })

    formatted_domains = []
    for obj in domains:
        dn = obj.get("distinguishedName", "")
        child_objects = get_child_objects(
            dn.upper(), value_to_id_cache, id_to_type_cache, BH_TYPE_LABEL_MAP
        )

        sid_bytes = obj.get("objectSid")
        guid_bytes = obj.get("objectGUID")
        domain_sid_str = ""
        if isinstance(sid_bytes, bytes):
            domain_sid_str = LDAP_SID(sid_bytes).formatCanonical()
        elif isinstance(sid_bytes, str) and sid_bytes.upper().startswith("S-1-"):
            domain_sid_str = sid_bytes.upper()
        domain_guid_str = str(UUID(bytes_le=guid_bytes)) if isinstance(guid_bytes, bytes) else guid_bytes

        # Liens GPO
        raw_gplinks = obj.get("gPLink", [])
        gplink_values = raw_gplinks if isinstance(raw_gplinks, list) else ([raw_gplinks] if raw_gplinks else [])
        main_domain_gplinks = []
        for gplink_str in gplink_values:
            if not gplink_str or not isinstance(gplink_str, str):
                continue
            try:
                link_part, options_part = gplink_str.split(';', 1)
                if not link_part.lower().startswith("[ldap://"):
                    continue
                link_dn = link_part[len("[ldap://"):].strip("]")
                link_options = int(options_part.strip('[]'))
                gpo_id = value_to_id_cache.get(link_dn.upper())
                if gpo_id:
                    main_domain_gplinks.append({"IsEnforced": bool(link_options & 0x1), "GUID": gpo_id.upper()})
            except Exception as e:
                logging.warning(f"Could not parse gPLink '{gplink_str}' for domain: {e}")

        # Récupère les ACEs du domaine (tous, pas de filtre)
        aces_domain, is_acl_protected_domain = _parse_aces(
            obj.get("nTSecurityDescriptor"),
            id_to_type_cache,
            domain_sid_str,
            "Domain",object_type_guid_map=objecttype_guid_map
        )
        aces_domain = dedupe_aces(aces_domain)
        # Préfixe les SIDs well-known comme BloodHound
        for ace in aces_domain:
            ace["PrincipalSID"] = prefix_well_known_sid(ace["PrincipalSID"], domain_name, domain_sid_str)

        props = {
            "name": f"{domain_name.upper()}",
            "domain": f"{domain_name.upper()}",
            "domainsid": domain_sid_str,
            "distinguishedname": dn.upper(),
            "description": obj.get("description", ""),
            "functionallevel": str(obj.get("msDS-Behavior-Version", "2016")),
            "highvalue": True,
            "isaclprotected": is_acl_protected_domain,
            "collected": True,
            "whencreated": _ldap_datetime_to_epoch(obj.get("whenCreated")),
        }

        domain_bh_entry = {
            "ObjectIdentifier": domain_sid_str,
            "Properties": props,
            "Trusts": [],
            "Aces": aces_domain,
            "Links": main_domain_gplinks,
            #"ChildObjects": childobjects_lookup.get(dn.upper(), []),
            "ChildObjects": child_objects,
            "GPOChanges": {
                "AffectedComputers": [],
                "DcomUsers": [],
                "LocalAdmins": [],
                "PSRemoteUsers": [],
                "RemoteDesktopUsers": []
            },
            "IsDeleted": False,
            "IsACLProtected": is_acl_protected_domain,
        }
        formatted_domains.append(domain_bh_entry)

    return {
        "data": formatted_domains,
        "meta": {
            "type": "domains",
            "count": len(formatted_domains),
            "version": 6
        }
    }
