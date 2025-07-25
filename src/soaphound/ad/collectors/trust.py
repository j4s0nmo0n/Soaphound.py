from uuid import UUID
from impacket.ldap.ldaptypes import LDAP_SID
from soaphound.ad.cache_gen import pull_all_ad_objects, _ldap_datetime_to_epoch
import json

def collect_trusts(ip=None, domain=None, username=None, auth=None, base_dn_override=None, cache_file=None):
    """
    Collecte tous les objets trustedDomain depuis l'annuaire ou un cache.
    """
    if cache_file:
        with open(cache_file, "r", encoding="utf-8") as f:
            cache_data = json.load(f)
        if isinstance(cache_data, dict):
            if "objects" in cache_data:
                objs = cache_data["objects"]
            elif "data" in cache_data:
                objs = cache_data["data"]
            else:
                objs = list(cache_data.values())
        else:
            objs = cache_data
        trusts = [
            o for o in objs
            if o.get("distinguishedName") and isinstance(o.get("distinguishedName"), str)
        ]
        print(f"[INFO] Trusts collected : {len(trusts)}")
        return trusts
    else:
        attributes = [
            "name", "objectGUID", "objectSid", "objectClass", "distinguishedName",
            "trustDirection", "trustType", "trustAttributes", "flatName", "trustPartner",
            "whenCreated", "securityIdentifier"
        ]
        query = "(objectClass=trustedDomain)"
        trusts = pull_all_ad_objects(
            ip=ip,
            domain=domain,
            username=username,
            auth=auth,
            query=query,
            attributes=attributes,
            base_dn_override=base_dn_override
        ).get("objects", [])
        
        print(f"[INFO] Trusts collected : {len(trusts)}")
        return [t for t in trusts if t.get("distinguishedName") and isinstance(t.get("distinguishedName"), str)]

def format_trusts(
    raw_trusts,
    domain,
    domain_sid,
    id_to_type_cache,
    value_to_id_cache,
    objecttype_guid_map
):
    formatted_trusts = []
    domain_upper = domain.upper()
    for obj in raw_trusts:
        dn = obj.get("distinguishedName", "")
        if isinstance(dn, list):
            dn = dn[0] if dn else ""
        guid_bytes = obj.get("objectGUID")
        trust_guid = str(UUID(bytes_le=guid_bytes)).upper() if isinstance(guid_bytes, bytes) else str(guid_bytes).upper()
        value_to_id_cache[dn.upper()] = trust_guid

        trust_partner = obj.get("trustPartner", "")
        flat_name = obj.get("flatName", "")
        trust_type = int(obj.get("trustType", 0) or 0)
        trust_direction = int(obj.get("trustDirection", 0) or 0)
        trust_attributes = int(obj.get("trustAttributes", 0) or 0)
        whencreated = _ldap_datetime_to_epoch(obj.get("whenCreated"))
        # SID
        sid_bytes = obj.get("objectSid")
        trust_sid = ""
        if isinstance(sid_bytes, bytes):
            trust_sid = LDAP_SID(sid_bytes).formatCanonical()
        elif isinstance(sid_bytes, str) and sid_bytes.upper().startswith("S-1-"):
            trust_sid = sid_bytes.upper()
        elif obj.get("securityIdentifier"):
            trust_sid = obj.get("securityIdentifier")

        props = {
            "name": trust_partner or flat_name,
            "trustpartner": trust_partner,
            "flatname": flat_name,
            "trusttype": trust_type,
            "trustdirection": trust_direction,
            "trustattributes": trust_attributes,
            "distinguishedname": dn.upper(),
            "domainsid": domain_sid,
            "trustsid": trust_sid,
            "whencreated": whencreated,
            "domain": domain_upper
        }

        trust_bh_entry = {
            "ObjectIdentifier": trust_guid,
            "Properties": props,
            "IsDeleted": False,
            "IsACLProtected": False
        }
        formatted_trusts.append(trust_bh_entry)
    return {
        "data": formatted_trusts,
        "meta": {
            "type": "trusts",
            "count": len(formatted_trusts),
            "version": 6
        }
    }
