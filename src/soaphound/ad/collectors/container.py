from uuid import UUID
from impacket.ldap.ldaptypes import LDAP_SID
from soaphound.ad.cache_gen import filetime_to_unix, _parse_aces, pull_all_ad_objects, BH_TYPE_LABEL_MAP, dedupe_aces, adws_objecttype_guid_map
import re
import unicodedata
import json
import os

def is_bloodhound_filtered_container(dn):
    """Filtre principal BloodHound : exclut containers techniques et containers GPO User/Machine."""
    dn_upper = dn.upper()
    if "CN=DOMAINUPDATES,CN=SYSTEM," in dn_upper:
        return True
    if "CN=POLICIES,CN=SYSTEM," in dn_upper and (dn_upper.startswith('CN=USER') or dn_upper.startswith('CN=MACHINE')):
        return True
    return False

def is_bloodhound_filtered_container_child(dn):
    """Filtre enfants BloodHound : exclut tout ce qui est sous Program Data ou System."""
    dn_upper = dn.upper()
    if "CN=PROGRAM DATA," in dn_upper:
        return True
    if "CN=SYSTEM," in dn_upper:
        return True
    return False

def is_bloodhound_exported_container(obj):
    """
    Filtre élargi pour coller à BloodHound :
    Garde containers standards & utiles, exclut les GUID purs et certains containers techniques/profonds.
    """
    name = obj.get("name", "")
    if isinstance(name, list):
        name = name[0] if name else ""
    dn = obj.get("distinguishedName", "")
    dn_upper = dn.upper()

    # Applique le filtre *BloodHound officiel* AVANT toute chose
    if is_bloodhound_filtered_container(dn):
        return False

    # Exclure containers à nom GUID (évite les sous-containers techniques des GPO)
    if isinstance(name, str) and re.fullmatch(r"[A-F0-9\-]{36}", name):
        return False

    # Exclure containers techniques/profonds (legacy, gardé par prudence)
    if "CN=OPERATIONS,CN=DOMAINUPDATES,CN=SYSTEM," in dn_upper:
        return False
    if "CN=DOMAINUPDATES,CN=SYSTEM," in dn_upper:
        return False

    # Garder :
    # - tout container dont le parent est DC=... (racine du domaine)
    # - tout container sous CN=SYSTEM ou CN=PROGRAM DATA (pas trop profond, pas GUID)
    if dn_upper.count(",DC=") == 2:
        return True
    if ",CN=PROGRAM DATA," in dn_upper:
        return True
    if ",CN=SYSTEM," in dn_upper:
        return True

    return False



def filter_bloodhound_container_aces(aces):
    """
    Filtre les ACEs pour ne garder que celles que BloodHound.py exporte typiquement pour les containers.
    Exclut par défaut AddKeyCredentialLink, AllExtendedRights, GenericWrite (et autres droits non standards).
    Garde typiquement: Owns, WriteDacl, WriteOwner, GenericAll (et éventuellement les droits hérités de base).
    """
    # Droits à exclure (case insensitive)
    excluded_rights = {
        "addkeycredentiallink", "allextendedrights", "genericwrite"
    }
    filtered = []
    for ace in aces:
        right = ace.get("RightName", "").lower()
        if right in excluded_rights:
            continue
        filtered.append(ace)
    return filtered


def _is_guid_str(s):
    return isinstance(s, str) and re.fullmatch(r"[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}", s, re.I)

def _is_interesting_container(obj):
    dn = obj.get("distinguishedName", "")
    if isinstance(dn, list):
        dn = dn[0] if dn else ""
    dn_upper = dn.upper()
    name = obj.get("name", "")
    if isinstance(name, list):
        name = name[0] if name else ""
    if "CN=OPERATIONS,CN=DOMAINUPDATES,CN=SYSTEM," in dn_upper:
        return False
    if "CN=DOMAINUPDATES,CN=SYSTEM," in dn_upper:
        return False
    if _is_guid_str(name):
        return False
    return True

def _get_parent_dn(dn):
    parts = dn.split(",", 1)
    return parts[1] if len(parts) == 2 else ""

def get_child_objects(container_dn_upper, value_to_id_cache, id_to_type_cache, BH_TYPE_LABEL_MAP):
    """
    Trouve les enfants directs d'un container/OU/domain via la logique cache_gen.
    N'inclut PAS les objets filtrés par BloodHound.
    """
    if isinstance(value_to_id_cache, str) and os.path.isfile(value_to_id_cache):
        with open(value_to_id_cache, "r", encoding="utf-8") as f:
            value_to_id_cache = json.load(f)
    children = []
    for item_dn_child_upper, item_child_id in value_to_id_cache.items():
        # Critère d'enfant direct
        if item_dn_child_upper != container_dn_upper and item_dn_child_upper.endswith("," + container_dn_upper):
            if item_dn_child_upper.count(',') == container_dn_upper.count(',') + 1:
                # Filtre enfant BloodHound (évite les sous-containers techniques)
                if is_bloodhound_filtered_container_child(item_dn_child_upper):
                    continue
                child_type_numeric = id_to_type_cache.get(item_child_id)
                child_type_label = BH_TYPE_LABEL_MAP.get(child_type_numeric, "Container").capitalize()
                children.append({
                    "ObjectIdentifier": item_child_id,
                    "ObjectType": child_type_label,
                    # PAS de DistinguishedName, conforme BloodHound.py
                })
    return children

def collect_containers(ip=None, domain=None, username=None, auth=None, base_dn_override=None, cache_file=None):
    """
    Si cache_file est fourni, charge les containers depuis ce cache sans collecte ADWS.
    Sinon, collecte en live via ADWS.
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
        containers = [
            c for c in objs
            if c.get("distinguishedName") and isinstance(c.get("distinguishedName"), str)
            and is_bloodhound_exported_container(c)
        ]
        print(f"[INFO] Containers collected : {len(containers)}")
        return containers
    else:
        attributes = [
            "distinguishedName",
            "name",
            "objectGUID",
            "isCriticalSystemObject",
            "objectClass",
            "objectCategory",
            "description",
            "whenCreated",
            "nTSecurityDescriptor",
        ]
        query = "(&(objectClass=container)(objectCategory=container))"

        containers = pull_all_ad_objects(
            ip=ip,
            domain=domain,
            username=username,
            auth=auth,
            query=query,
            attributes=attributes,
            base_dn_override=base_dn_override
        ).get("objects", [])

        if (
            len(containers) == 1
            and isinstance(containers[0], dict)
            and any(isinstance(v, list) and len(v) > 1 for v in containers[0].values())
        ):
            maxlen = max(len(v) for v in containers[0].values() if isinstance(v, list))
            new_containers = []
            for i in range(maxlen):
                obj = {}
                for k, v in containers[0].items():
                    if isinstance(v, list):
                        obj[k] = v[i] if i < len(v) else None
                    else:
                        obj[k] = v
                new_containers.append(obj)
            containers = new_containers

        containers = [
            c for c in containers
            if c.get("distinguishedName") and isinstance(c.get("distinguishedName"), str)
            and is_bloodhound_exported_container(c)
        ]
        print(f"[INFO] Containers collected : {len(containers)}")
        return containers

def format_containers(
    raw_containers,
    domain,
    main_domain_root_dn,
    id_to_type_cache,
    value_to_id_cache,
    all_collected_items,
    objecttype_guid_map
):
    from uuid import UUID
    import unicodedata
    from impacket.ldap.ldaptypes import LDAP_SID

    # Récupère le SID du domaine principal comme dans domain.py
    main_domain_sid = ""
    if isinstance(main_domain_root_dn, dict):
        sid_bytes = main_domain_root_dn.get("objectSid")
        if isinstance(sid_bytes, bytes):
            main_domain_sid = LDAP_SID(sid_bytes).formatCanonical()
        elif isinstance(sid_bytes, str) and sid_bytes.upper().startswith("S-1-"):
            main_domain_sid = sid_bytes.upper()

    def filter_bloodhound_container_aces(aces):
        excluded_rights = {
            "addkeycredentiallink", "allextendedrights", "genericwrite"
        }
        filtered = []
        for ace in aces:
            right = ace.get("RightName", "").lower()
            if right in excluded_rights:
                continue
            filtered.append(ace)
        return filtered

    formatted_containers = []
    for obj in raw_containers:
        dn = obj.get("distinguishedName", "")
        if isinstance(dn, list):
            dn = dn[0] if dn else ""
        container_dn_upper = unicodedata.normalize('NFKC', dn).upper()

        guid_bytes = obj.get("objectGUID")
        object_guid_str = str(UUID(bytes_le=guid_bytes)) if isinstance(guid_bytes, bytes) else guid_bytes

        aces, is_acl_protected = _parse_aces(
            obj.get("nTSecurityDescriptor"),
            id_to_type_cache,
            object_guid_str,
            "Container", object_type_guid_map=objecttype_guid_map
        )
        #aces = filter_bloodhound_container_aces(aces)
        #aces = dedupe_aces(aces)
        
        name = obj.get("name", "")
        if isinstance(name, list):
            name = name[0] if name else ""
        description = obj.get("description", "")
        if isinstance(description, list):
            description = description[0] if description else ""

        # domainsid: prioritaire sur l'objet, sinon SID du domaine principal (toujours rempli !)
        domainsid = obj.get("domainsid") or obj.get("domainSid") or main_domain_sid or ""

        highvalue = obj.get("highvalue", False)
        isaclprotected = obj.get("isaclprotected", False)

        props = {
            "domain": domain.upper(),
            "name": f"{name.upper()}@{domain.upper()}",
            "distinguishedname": container_dn_upper,
            "domainsid": domainsid,
            "highvalue": highvalue,
            "description": description,
            "whencreated": filetime_to_unix(obj.get("whenCreated")),
            "isaclprotected": isaclprotected,
        }

        container_bh_entry = {
            "ObjectIdentifier": object_guid_str,
            "Properties": props,
            "Aces": aces,
            "ChildObjects": get_child_objects(container_dn_upper, value_to_id_cache, id_to_type_cache, BH_TYPE_LABEL_MAP),
            "IsDeleted": False,
            "IsACLProtected": is_acl_protected,
        }
        formatted_containers.append(container_bh_entry)
   # print(f"[DEBUG] Nombre de containers formatés: {len(formatted_containers)}")
   # print(f"[DEBUG] Exemples: {[c['Properties']['name'] for c in formatted_containers[:5]]}")
    return {
        "data": formatted_containers,
        "meta": {
            "type": "containers",
            "count": len(formatted_containers),
            "version": 6
        }
    }
