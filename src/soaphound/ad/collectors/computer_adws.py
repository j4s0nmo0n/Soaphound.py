from uuid import UUID
from impacket.ldap.ldaptypes import LDAP_SID
from soaphound.ad.cache_gen import pull_all_ad_objects, _parse_aces, dedupe_aces, filetime_to_unix, BH_TYPE_LABEL_MAP
from soaphound.lib.utils import ADUtils
from soaphound.ad.adws import WELL_KNOWN_SIDS

def collect_computers_adws(
    ip=None,
    domain=None,
    username=None,
    auth=None,
    base_dn_override=None,
    cache_file=None,
    adws_object_classes=None,
    has_laps=False,
    has_lapsv2=False
):
    """
        Collect all AD computers via ADWS only (with ACLs, LAPS, without sessions or RPC).
    """
    import json

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
        computers = [
            o for o in objs
            if o.get("distinguishedName") and isinstance(o.get("distinguishedName"), str)
        ]
        return computers

    attributes = [
        "name", "objectGUID", "objectSid", "objectClass", "distinguishedName",
        "nTSecurityDescriptor", "whenCreated", "description", "sAMAccountName", "dNSHostName", "userAccountControl",
        "operatingSystem", "operatingSystemVersion", "servicePrincipalName",
        "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-AllowedToDelegateTo",
        "lastLogon", "lastLogonTimestamp", "adminCount", "primaryGroupID", "sIDHistory"
    ]
    laps_attributes = [
        "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
        "msLAPS-EncryptedPassword", "msLAPS-PasswordExpirationTime",
        "msLAPS-Password", "msLAPS-EncryptedPasswordHistory",
        "msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory"
    ]

    lapsv2_attributes = [
        "msLAPS-EncryptedPassword", "msLAPS-PasswordExpirationTime",
    ]

    if has_laps or has_lapsv2:
        for laps_attr in laps_attributes:
            if laps_attr not in attributes:
                attributes.append(laps_attr)
    if has_lapsv2:
        for laps_attr in lapsv2_attributes:
            if laps_attr not in attributes:
                attributes.append(laps_attr)


    gmsa_filter = '(!(objectClass=msDS-GroupManagedServiceAccount))' if 'msDS-GroupManagedServiceAccount' in (adws_object_classes or []) else ''
    smsa_filter = '(!(objectClass=msDS-ManagedServiceAccount))' if 'msDS-ManagedServiceAccount' in (adws_object_classes or []) else ''
    query = f"(&(sAMAccountType=805306369){gmsa_filter}{smsa_filter})"

    raw_objects = pull_all_ad_objects(
        ip=ip,
        domain=domain,
        username=username,
        auth=auth,
        query=query,
        attributes=attributes,
        base_dn_override=base_dn_override
    ).get("objects", [])

    for obj in raw_objects:
        oc = ADUtils.get_entry_property(obj, "objectClass", default=[])
        if isinstance(oc, str):
            obj["objectClass"] = [oc]
        elif oc is None:
            obj["objectClass"] = []
        dn = ADUtils.get_entry_property(obj, "distinguishedName", default="")
        if isinstance(dn, list):
            obj["distinguishedName"] = dn[0] if dn else ""
        guid = ADUtils.get_entry_property(obj, "objectGUID")
        if isinstance(guid, bytes):
            try:
                obj["objectGUID"] = str(UUID(bytes_le=guid)).upper()
            except Exception:
                pass
    print(f"[INFO] Computers collected : {len(raw_objects)}")        
    return raw_objects

def prefix_well_known_sid(sid: str, domain_name: str, domain_sid: str, well_known_sids=WELL_KNOWN_SIDS):
    sid = sid.upper()
    domain_sid = domain_sid.upper()
    if not sid: return sid
    if sid.startswith(domain_sid + "-") or sid == domain_sid:
        return sid
    if sid in well_known_sids or sid.startswith("S-1-5-32-"):
        return f"{domain_name.upper()}-{sid}"
    return sid

def format_computers_adws(
    computers,
    domain,
    domain_sid,
    id_to_type_cache,
    value_to_id_cache,
    objecttype_guid_map
):
    formatted_computers = []
    domain_upper = domain.upper()

    for obj in computers:
        dn = obj.get("distinguishedName", "")
        if isinstance(dn, list):
            dn = dn[0] if dn else ""
        comp_guid = obj.get("objectGUID")
        if isinstance(comp_guid, bytes):
            comp_guid = str(UUID(bytes_le=comp_guid)).upper()
        elif isinstance(comp_guid, str):
            comp_guid = comp_guid.upper()
        value_to_id_cache[dn.upper()] = comp_guid

        sid_bytes = obj.get("objectSid")
        comp_sid = None
        if isinstance(sid_bytes, bytes):
            comp_sid = LDAP_SID(sid_bytes).formatCanonical()
        elif isinstance(sid_bytes, str) and sid_bytes.upper().startswith("S-1-"):
            comp_sid = sid_bytes.upper()
        if not comp_sid:
            continue

        sAM = obj.get("sAMAccountName", "")
        hostname = obj.get("dNSHostName", "") or sAM[:-1].upper()
        uac = obj.get("userAccountControl", 0)
        try:
            uac = int(uac)
        except Exception:
            uac = 0
        description = obj.get("description", "")
        serviceprincipalnames = obj.get("servicePrincipalName", [])
        delegatehosts_raw = obj.get("msDS-AllowedToDelegateTo", [])
        if not isinstance(delegatehosts_raw, list):
            if delegatehosts_raw:
                delegatehosts_raw = [delegatehosts_raw]
            else:
                delegatehosts_raw = []

        lastlogon = filetime_to_unix(obj.get("lastLogon"))
        lastlogontimestamp = filetime_to_unix(obj.get("lastLogonTimestamp"))
        if lastlogontimestamp == 0 or lastlogontimestamp == -11644473600:
            lastlogontimestamp = -1
        pwdlastset = filetime_to_unix(obj.get("pwdLastSet"))
        whencreated = filetime_to_unix(obj.get("whenCreated"))

        sidhistory = obj.get("sIDHistory", [])
        if not isinstance(sidhistory, list): sidhistory = []

        # LAPS Detection
        laps_signals = [
            "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
            "msLAPS-EncryptedPassword", "msLAPS-PasswordExpirationTime",
            "msLAPS-Password", "msLAPS-EncryptedPasswordHistory",
            "msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory"
        ]
        has_laps = any(obj.get(attr) not in (None, "", b"") for attr in laps_signals)

        # ---  ACLs from nTSecurityDescriptor via _parse_aces (same as BH.py) ---
        aces_computer, isaclprotected = _parse_aces(
            obj.get("nTSecurityDescriptor"),
            id_to_type_cache,
            comp_sid,
            "Computer",
            object_type_guid_map=objecttype_guid_map
        )
        aces_computer = dedupe_aces(aces_computer)
        for ace in aces_computer:
            ace["PrincipalSID"] = prefix_well_known_sid(ace["PrincipalSID"], domain, domain_sid)

        props = {
            "name": hostname.upper() if hostname.upper().endswith(domain_upper) else f"{hostname.upper()}.{domain_upper}",
            "domain": domain_upper,
            "domainsid": domain_sid,
            "highvalue": False,
            "distinguishedname": dn.upper() if dn else None,
            "enabled": (uac & 2) == 0,
            "unconstraineddelegation": (uac & 0x00080000) == 0x00080000,
            "trustedtoauth": (uac & 0x01000000) == 0x01000000,
            "operatingsystem": obj.get("operatingSystem", None),
            "operatingsystemversion": obj.get("operatingSystemVersion"),
            "description": description if description else None,
            "samaccountname": sAM,
            "dnshostname": obj.get("dNSHostName", ""),
            "admincount": int(obj.get("adminCount", 0) or 0) == 1,
            "serviceprincipalnames": serviceprincipalnames,
            "hasspn": bool(serviceprincipalnames),
            "whencreated": whencreated,
            "lastlogon": lastlogon,
            "lastlogontimestamp": lastlogontimestamp,
            "pwdlastset": pwdlastset,
            "isaclprotected": isaclprotected,
            "haslaps": has_laps,
            "sidhistory": [LDAP_SID(x).formatCanonical() for x in sidhistory],
            "allowedtodelegate": delegatehosts_raw
        }

        #  LAPS attributes if present
        laps_attrs_to_export = [
            "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
            "msLAPS-EncryptedPassword", "msLAPS-PasswordExpirationTime",
            "msLAPS-Password", "msLAPS-EncryptedPasswordHistory",
            "msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory"
        ]
        for attr in laps_attrs_to_export:
            if obj.get(attr) is not None:
                val = obj[attr]
                if isinstance(val, bytes):
                    import base64
                    val = base64.b64encode(val).decode('ascii')
                props[attr] = val

        computer_bh_entry = {
            "ObjectIdentifier": comp_sid,
            "AllowedToAct": [],
            "PrimaryGroupSID": f"{domain_sid}-{obj.get('primaryGroupID', 515)}",
            "Properties": props,
            "Aces": aces_computer,
            "Sessions": {
                "Collected": False,
                "FailureReason": "ADWS-only mode: not collected",
                "Results": []
            },
            "PrivilegedSessions": {
                "Collected": False,
                "FailureReason": "ADWS-only mode: not collected",
                "Results": []
            },
            "RegistrySessions": {
                "Collected": False,
                "FailureReason": "ADWS-only mode: not collected",
                "Results": []
            },
            "LocalGroups": [],
            "UserRights": [],
            "AllowedToDelegate": [],
            "HasSIDHistory": [],
            "IsDeleted": False,
            "Status": None,
            "IsACLProtected": isaclprotected,
            "ContainedBy": None,
            "DumpSMSAPassword": []
        }
        formatted_computers.append(computer_bh_entry)
    return {
        "data": formatted_computers,
        "meta": {
            "methods": 0,
            "type": "computers",
            "count": len(formatted_computers),
            "version": 6
        }
    }
