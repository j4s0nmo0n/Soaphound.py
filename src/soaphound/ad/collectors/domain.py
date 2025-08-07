from uuid import UUID
import logging
from impacket.ldap.ldaptypes import LDAP_SID

from soaphound.lib.utils import ADUtils
from soaphound.ad.cache_gen import pull_all_ad_objects, filetime_to_unix, _parse_aces, dedupe_aces,adws_objecttype_guid_map
from soaphound.ad.adws import WELL_KNOWN_SIDS
from .container import get_child_objects, BH_TYPE_LABEL_MAP
from .trust import trust_to_bh_output

def collect_domains(ip, domain, username, auth, base_dn_override=None, domain_functionality=None):
    """
    Collect domain-type objects (domainDNS only)
    """
    attributes = [
        "name", "objectGUID", "objectSid", "objectClass", "distinguishedName",
        "nTSecurityDescriptor", "whenCreated", "cn", "gPLink"
    ]
    domains = pull_all_ad_objects(
        ip=ip,
        domain=domain,
        username=username,
        auth=auth,
        query="(objectClass=domain)",
        attributes=attributes,
        base_dn_override=base_dn_override
    ).get("objects", [])
    print(f"[INFO] Domains collected : {len(domains)}")
    return domains



def sid_to_principal_type(sid):
    sid = sid.upper()
    # able of well-known SIDs
    if sid in ADUtils.WELLKNOWN_SIDS:
        return ADUtils.WELLKNOWN_SIDS[sid][1].capitalize()
    # Final mapping by RID
    try:
        rid = int(sid.split('-')[-1])
    except Exception:
        return "Unknown"
    if rid in [
        512, 516, 518, 519, 520, 521, 522, 525, 526, 527, 553, 544, 545, 546, 547, 548, 549, 
        550, 551, 552
    ]:
        return "Group"
    if rid == 500:
        return "User"
    return "Unknown"
    

def prefix_well_known_sid(sid: str, domain_name: str, domain_sid: str, well_known_sids=WELL_KNOWN_SIDS):
    sid = sid.upper()
    domain_sid = domain_sid.upper()
    if sid.startswith(domain_sid + "-") or sid == domain_sid:
        return sid
    # Add the prefix if S-1-5-32-XXX or if it's in the well-known table
    if sid in well_known_sids or sid.startswith("S-1-5-32-"):
        return f"{domain_name.upper()}-{sid}"
    return sid

def format_domains(domains, domain_name, domain_root_dn, id_to_type_cache, value_to_id_cache, all_collected_items, objecttype_guid_map, all_trusts, domain_functionality=None):
    # Construction of the lookup from parent DN to direct children (containers, OUs, etc.)
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

        # GPO Link
        raw_gplink = obj.get("gPLink", "")
        main_domain_gplinks = []
        if raw_gplink and isinstance(raw_gplink, str):
            for dn, option in ADUtils.parse_gplink_string(raw_gplink):
                gpo_id = value_to_id_cache.get(dn.upper())
                if gpo_id:
                    main_domain_gplinks.append({
                        "IsEnforced": bool(option & 0x1),
                        "GUID": gpo_id.upper()
                    })

        # Retrieve the domain's ACEs (all of them, no filtering)
        aces_domain, is_acl_protected_domain = _parse_aces(
            obj.get("nTSecurityDescriptor"),
            id_to_type_cache,
            domain_sid_str,
            "Domain",object_type_guid_map=objecttype_guid_map
        )
        aces_domain = dedupe_aces(aces_domain)
        # Prefix well-known SIDs like BloodHound
        for ace in aces_domain:
            ace["PrincipalSID"] = prefix_well_known_sid(ace["PrincipalSID"], domain_name, domain_sid_str)
        
        try:
            functional_level = ADUtils.FUNCTIONAL_LEVELS.get(int(domain_functionality), "Unknown")
        except (TypeError, ValueError):
            functional_level = "Unknown"

        
        props = {
            "name": f"{domain_name.upper()}",
            "domain": f"{domain_name.upper()}",
            "domainsid": domain_sid_str,
            "distinguishedname": obj.get("distinguishedName", "").upper(),
            "description": obj.get("description", ""),
            "functionallevel": functional_level,
            "highvalue": True,
            "isaclprotected": is_acl_protected_domain,
            "collected": True,
            "whencreated": filetime_to_unix(obj.get("whenCreated")),
        }
        
        # Find all trusts where the source domain SID matches this domain
        trusts_for_domain = []
        for trust in all_trusts:
            # Compare the domain SID (make sure both are uppercase for robustness)
            if trust.get("domainsid", "").upper() == domain_sid_str.upper():
                trusts_for_domain.append(trust_to_bh_output(trust))


        domain_bh_entry = {
            "ObjectIdentifier": domain_sid_str,
            "Properties": props,
            "Trusts": trusts_for_domain,
            "Aces": aces_domain,
            "Links": main_domain_gplinks,
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
