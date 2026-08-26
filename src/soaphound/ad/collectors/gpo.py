from uuid import UUID
import unicodedata
import re
from impacket.ldap.ldaptypes import LDAP_SID
from soaphound.ad.cache_gen import pull_all_ad_objects, filetime_to_unix, _parse_aces, adws_objecttype_guid_map
from soaphound.ad.adws import WELL_KNOWN_SIDS
import json
import os

BH_VALID_RIGHTS = {"Owns", "GenericWrite", "WriteOwner", "WriteDacl", "AllExtendedRights"}

def collect_gpos(ip=None, domain=None, username=None, auth=None, base_dn_override=None, cache_file=None):
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
        gpos = [g for g in objs if g.get("distinguishedName") and isinstance(g.get("distinguishedName"), str)]
        return gpos
    else:
        attributes = [
            "name", "displayName", "objectGUID", "nTSecurityDescriptor",
            "distinguishedName", "gPCFileSysPath", "versionNumber", "flags",
            "gPCFunctionalityVersion", "whenCreated", "description",
            "gPCMachineExtensionNames", "gPCUserExtensionNames", "gPCWQLFilter"
        ]
        query = "(objectClass=groupPolicyContainer)"
        gpos = pull_all_ad_objects(
            ip=ip,
            domain=domain,
            username=username,
            auth=auth,
            query=query,
            attributes=attributes,
            base_dn_override=base_dn_override
        ).get("objects", [])
        result = [g for g in gpos if g.get("distinguishedName") and isinstance(g.get("distinguishedName"), str)]
        print(f"[INFO] GPOs collected : {len(result)}")
        return result
        #return [g for g in gpos if g.get("distinguishedName") and isinstance(g.get("distinguishedName"), str)]


def collect_wmi_filters(ip, domain, username, auth, base_dn):
    """Collect msWMI-Som objects and return a dict keyed by GUID (upper, no braces)."""
    wmi_base = f"CN=SOM,CN=WMIPolicy,CN=System,{base_dn}"
    try:
        results = pull_all_ad_objects(
            ip=ip, domain=domain, username=username, auth=auth,
            query="(objectClass=msWMI-Som)",
            attributes=["distinguishedName", "msWMI-ID", "msWMI-Name", "msWMI-Parm1", "msWMI-Author", "msWMI-Parm2"],
            base_dn_override=wmi_base
        ).get("objects", [])
    except Exception:
        return {}

    wmi_by_id = {}
    for obj in results:
        wmi_id = obj.get("msWMI-ID") or obj.get("mswmi-id") or ""
        if isinstance(wmi_id, list):
            wmi_id = wmi_id[0] if wmi_id else ""
        if not wmi_id:
            continue
        clean_id = wmi_id.strip("{}").upper()
        name_val = obj.get("msWMI-Name") or obj.get("mswmi-name") or ""
        if isinstance(name_val, list):
            name_val = name_val[0] if name_val else ""
        wmi_by_id[clean_id] = {
            "name": name_val,
            "description": obj.get("msWMI-Parm1") or obj.get("mswmi-parm1") or "",
            "query": obj.get("msWMI-Parm2") or obj.get("mswmi-parm2") or "",
            "author": obj.get("msWMI-Author") or obj.get("mswmi-author") or "",
            "dn": obj.get("distinguishedName", ""),
        }
    print(f"[INFO] WMI filters collected : {len(wmi_by_id)}")
    return wmi_by_id


def prefix_well_known_sid(sid: str, domain_name: str, domain_sid: str, well_known_sids=WELL_KNOWN_SIDS):
    sid = sid.upper()
    domain_sid = domain_sid.upper()
    if sid.startswith(domain_sid + "-") or sid == domain_sid:
        return sid
    if sid in well_known_sids or sid.startswith("S-1-5-32-"):
        return f"{domain_name.upper()}-{sid}"
    return sid

def filter_bloodhound_gpo_aces(aces):
    return [
            {
        "RightName": ace["RightName"],
        "IsInherited": ace["IsInherited"],
        "PrincipalSID": ace["PrincipalSID"],
        "PrincipalType": ace["PrincipalType"]
    }
        for ace in aces
        if not ace.get("IsInherited", False) and ace.get("RightName") in BH_VALID_RIGHTS
    ]

def _resolve_wmi_filter(raw_wql_filter, wmi_filters):
    """Extract the WMI filter GUID from gPCWQLFilter and return its metadata, or None."""
    if not raw_wql_filter or not wmi_filters:
        return None
    m = re.search(r'\{([A-F0-9\-]{36})\}', raw_wql_filter, re.IGNORECASE)
    if not m:
        return None
    filter_guid = m.group(1).upper()
    entry = wmi_filters.get(filter_guid)
    if not entry:
        return None
    return {
        "id": filter_guid,
        "name": entry.get("name", ""),
        "query": entry.get("query", "") or None,
        "author": entry.get("author", "") or None,
    }


def format_gpos(
    raw_gpos,
    domain,
    main_domain_sid,
    id_to_type_cache,
    value_to_id_cache,
    objecttype_guid_map,
    wmi_filters=None
):
    formatted_gpos = []
    domain_upper = domain.upper()
    for obj in raw_gpos:
        dn = obj.get("distinguishedName", "")
        if isinstance(dn, list):
            dn = dn[0] if dn else ""
        gpo_dn_upper = unicodedata.normalize('NFKC', dn).upper()
        guid_bytes = obj.get("objectGUID")
        gpo_guid = str(UUID(bytes_le=guid_bytes)).upper() if isinstance(guid_bytes, bytes) else str(guid_bytes).upper()
        value_to_id_cache[gpo_dn_upper] = gpo_guid

        # ACEs on GPO
        aces_gpo, is_acl_protected_gpo = _parse_aces(
            obj.get("nTSecurityDescriptor"),
            id_to_type_cache,
            gpo_guid,
            "GPO", object_type_guid_map=objecttype_guid_map
        )
        # Prefix SIDs

        for ace in aces_gpo:
            ace["PrincipalSID"] = prefix_well_known_sid(ace["PrincipalSID"], domain, main_domain_sid)
        # Filtrer comme BloodHound.py
        #aces_gpo = filter_bloodhound_gpo_aces(aces_gpo)

        # Name: displayName ou name, format BloodHound
        name = obj.get("displayName") or obj.get("name") or ""
        if isinstance(name, list):
            name = name[0] if name else ""
        name = f"{name.upper()}@{domain_upper}"

        # gpcpath (UNC, casing)
        gpcfilesyspath = obj.get("gPCFileSysPath", "") or ""
        gpcpath = gpcfilesyspath
        if gpcpath:
            gpcpath = gpcpath.replace("sysvol", "SYSVOL").replace("policies", "POLICIES")
            if gpcpath.startswith("\\\\"):
                left, right = gpcpath[2:].split("\\", 1)
                left = domain_upper
                gpcpath = f"\\\\{left}\\{right}"

        description = obj.get("description", None)

        props = {
            "domain": domain.upper(),
            "name": name,
            "distinguishedname": gpo_dn_upper,
            "domainsid": main_domain_sid,
            "highvalue": False,
            "isenabled": int(obj.get("flags") or 0) != 3,
            "gpcpath": gpcpath or None,
            "description": description,
            "machineextensionnames": obj.get("gPCMachineExtensionNames") or None,
            "userextensionnames": obj.get("gPCUserExtensionNames") or None,
            "wmifilter": _resolve_wmi_filter(obj.get("gPCWQLFilter"), wmi_filters),
            "whencreated": filetime_to_unix(obj.get("whenCreated")),
            "isaclprotected": is_acl_protected_gpo,
        }

        
        gpo_bh_entry = {
            "ObjectIdentifier": gpo_guid,
            "Properties": props,
            "Aces": aces_gpo,
            "IsDeleted": False,
            "IsACLProtected": is_acl_protected_gpo
        }
        formatted_gpos.append(gpo_bh_entry)
    return {
        "data": formatted_gpos,
        "meta": {
            "methods": 0,
            "type": "gpos",
            "count": len(formatted_gpos),
            "version": 6
        }
    }
