"""
SYSVOL GPO parser for BloodHound GPOChanges.

Reads Groups.xml and GptTmpl.inf from SYSVOL over SMB to populate
LocalAdmins, RemoteDesktopUsers, DcomUsers, PSRemoteUsers, and
AffectedComputers for each domain object.
"""
import io
import logging
import re
import configparser
from base64 import b64decode
from xml.etree import ElementTree

from impacket.smbconnection import SMBConnection

log = logging.getLogger(__name__)

# SIDs for built-in local groups we care about
_LOCAL_GROUP_SIDS = {
    "S-1-5-32-544": "LocalAdmins",
    "S-1-5-32-555": "RemoteDesktopUsers",
    "S-1-5-32-562": "DcomUsers",
    "S-1-5-32-580": "PSRemoteUsers",
}

# Privilege rights that map directly to BloodHound GPOChanges categories
_PRIVRIGHT_TO_CATEGORY = {
    "seremoteinteractivelogonright": "RemoteDesktopUsers",
}

# Privilege rights worth tracking even without a BH category mapping
_TRACKED_PRIVRIGHTS = {
    "seremoteinteractivelogonright",
    "senetworklogonright",
    "seinteractivelogonright",
    "seservicelogonright",
    "sebatchlogonright",
    "setcbprivilege",
    "sedebugprivilege",
    "seimpersonateprivilege",
    "seloaddriverprivilege",
    "sebackupprivilege",
    "serestoreprivilege",
    "setakeownershipprivilege",
}

# Canonical group names that also resolve to the categories above
_LOCAL_GROUP_NAMES = {
    "administrators": "LocalAdmins",
    "remote desktop users": "RemoteDesktopUsers",
    "distributed com users": "DcomUsers",
    "remote management users": "PSRemoteUsers",
}

# AES-256 key published by Microsoft (GPP cpassword)
_GPP_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
)


# ---------------------------------------------------------------------------
# SMB helpers
# ---------------------------------------------------------------------------

def connect_sysvol(ip, domain, username, auth):
    """
    Open an SMBConnection authenticated via the same auth object used for ADWS.
    Returns the connection object or None on failure.
    """
    try:
        from soaphound.ad.adws import NTLMAuth, KerberosAuth

        conn = SMBConnection(ip, ip, sess_port=445, timeout=10)

        if isinstance(auth, KerberosAuth):
            conn.kerberosLogin(username, "", domain, "", "", kdcHost=ip)
        else:
            # NTLMAuth stores password as .password and NT hash as .nt
            password = getattr(auth, "password", "") or ""
            nt_hash = getattr(auth, "nt", "") or ""
            lm_hash = ""
            conn.login(username, password, domain, lmhash=lm_hash, nthash=nt_hash)

        return conn
    except Exception as exc:
        log.warning("SYSVOL SMB connection failed (%s): %s", ip, exc)
        return None


def _read_smb_file(conn, share, path):
    """Download a file from SMB and return its raw bytes, or None on error."""
    buf = io.BytesIO()
    try:
        conn.getFile(share, path, buf.write)
        return buf.getvalue()
    except Exception as exc:
        log.debug("SYSVOL read failed for %s\\%s: %s", share, path, exc)
        return None


def _decode_text(data):
    """Decode bytes as UTF-16LE, then UTF-8, then latin-1 fallback."""
    if data is None:
        return ""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


# ---------------------------------------------------------------------------
# GPP cpassword decryption
# ---------------------------------------------------------------------------

def _decrypt_gpp_cpassword(cpassword):
    """Decrypt a GPP cpassword value. Returns plaintext or empty string."""
    if not cpassword:
        return ""
    try:
        from Crypto.Cipher import AES

        # Pad to multiple of 16
        padded = cpassword + "=" * (4 - len(cpassword) % 4) if len(cpassword) % 4 else cpassword
        data = b64decode(padded)
        cipher = AES.new(_GPP_KEY, AES.MODE_CBC, iv=b"\x00" * 16)
        decrypted = cipher.decrypt(data)
        # Strip PKCS#7 padding
        pad_len = decrypted[-1]
        return decrypted[:-pad_len].decode("utf-16-le", errors="replace")
    except Exception as exc:
        log.debug("GPP cpassword decrypt failed: %s", exc)
        return ""


# ---------------------------------------------------------------------------
# Groups.xml parser
# ---------------------------------------------------------------------------

def parse_groups_xml(content):
    """
    Parse Machine/Preferences/Groups/Groups.xml.
    Returns a dict {"LocalAdmins": [sids], "RemoteDesktopUsers": [sids], ...}
    and "GPPPasswords": [{"username": ..., "password": ...}].
    """
    result = {k: [] for k in _LOCAL_GROUP_SIDS.values()}
    result["GPPPasswords"] = []

    if not content:
        return result

    text = _decode_text(content) if isinstance(content, bytes) else content
    try:
        root = ElementTree.fromstring(text)
    except Exception as exc:
        log.debug("Groups.xml parse error: %s", exc)
        return result

    for group_el in root.findall(".//Group"):
        props = group_el.find("Properties")
        if props is None:
            continue

        # Detect which local group this modifies
        category = None
        group_sid = (props.get("groupSid") or "").upper().strip()
        group_name = (props.get("groupName") or "").strip()

        if group_sid in _LOCAL_GROUP_SIDS:
            category = _LOCAL_GROUP_SIDS[group_sid]
        else:
            for name_key, cat in _LOCAL_GROUP_NAMES.items():
                if name_key in group_name.lower():
                    category = cat
                    break

        if category is None:
            continue

        # Collect members being added
        for member in group_el.findall(".//Member"):
            member_action = member.get("action", "ADD").upper()
            if member_action not in ("ADD", ""):
                continue
            member_sid = (member.get("sid") or "").strip().upper()
            if member_sid:
                result[category].append(member_sid)

        # GPP password detection (separate from group membership)
        cpassword = props.get("cpassword") or ""
        username = props.get("userName") or props.get("accountName") or ""
        if cpassword:
            plaintext = _decrypt_gpp_cpassword(cpassword)
            result["GPPPasswords"].append({
                "username": username,
                "cpassword": cpassword,
                "plaintext": plaintext,
            })

    return result


# ---------------------------------------------------------------------------
# GptTmpl.inf parser
# ---------------------------------------------------------------------------

def _parse_sid_list(value):
    """Split a comma-separated SID list from GptTmpl.inf, strip leading '*'."""
    sids = []
    for token in value.split(","):
        sid = token.strip().lstrip("*").upper()
        if sid:
            sids.append(sid)
    return sids


def parse_gpttmpl_inf(content):
    """
    Parse Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf.

    Returns a dict with:
      - BH category keys (LocalAdmins, RemoteDesktopUsers, DcomUsers, PSRemoteUsers)
        populated from [Group Membership] and mapped privilege rights.
      - "PrivilegeRights": {priv_name: [sids]} for all tracked privilege assignments.
    """
    result = {k: [] for k in _LOCAL_GROUP_SIDS.values()}
    result["PrivilegeRights"] = {}

    if not content:
        return result

    text = _decode_text(content) if isinstance(content, bytes) else content
    text = text.lstrip("﻿")  # strip BOM

    cfg = configparser.RawConfigParser(strict=False)
    try:
        cfg.read_string(text)
    except Exception as exc:
        log.debug("GptTmpl.inf parse error: %s", exc)
        return result

    # --- [Group Membership] ---
    if cfg.has_section("Group Membership"):
        for key, value in cfg.items("Group Membership"):
            key_clean = key.lstrip("*").upper()
            if not key_clean.endswith("__MEMBERS"):
                continue
            group_sid = key_clean[: key_clean.index("__MEMBERS")]
            category = _LOCAL_GROUP_SIDS.get(group_sid)
            if not category:
                continue
            result[category].extend(_parse_sid_list(value))

    # --- [Privilege Rights] ---
    if cfg.has_section("Privilege Rights"):
        for priv, value in cfg.items("Privilege Rights"):
            priv_lower = priv.lower()
            if priv_lower not in _TRACKED_PRIVRIGHTS:
                continue
            sids = _parse_sid_list(value)
            if sids:
                result["PrivilegeRights"][priv_lower] = sids
            # Map to BH GPOChanges category when applicable
            category = _PRIVRIGHT_TO_CATEGORY.get(priv_lower)
            if category:
                result[category].extend(sids)

    return result


# ---------------------------------------------------------------------------
# Main collector
# ---------------------------------------------------------------------------

def collect_gpo_sysvol_changes(conn, domain, gpo_guids, id_to_type_cache, value_to_id_cache):
    """
    For each GPO GUID, read Groups.xml and GptTmpl.inf from SYSVOL and
    aggregate the GPOChanges dict (LocalAdmins, RDP, DCOM, PSRemote).

    Returns:
        gpo_changes: dict with keys matching BloodHound GPOChanges format
        gpp_passwords: list of dicts {"gpo_guid", "username", "cpassword", "plaintext"}
        privilege_rights: dict {priv_name: [sids]} aggregated across all GPOs
    """
    BH_TYPE_LABEL_MAP = {
        0: "User", 1: "Computer", 2: "Group", 3: "Gpo",
        4: "Domain", 5: "OU", 6: "Container",
    }

    aggregated = {
        "LocalAdmins": set(),
        "RemoteDesktopUsers": set(),
        "DcomUsers": set(),
        "PSRemoteUsers": set(),
    }
    all_privilege_rights = {}
    all_gpp_passwords = []

    guids_with_changes = set()

    for guid in gpo_guids:
        guid_upper = guid.upper().strip("{}")
        gpo_dir = f"\\{domain}\\Policies\\{{{guid_upper}}}"
        pre_counts = {cat: len(aggregated[cat]) for cat in aggregated}

        # Machine-side Groups.xml
        xml_path = gpo_dir + "\\Machine\\Preferences\\Groups\\Groups.xml"
        xml_data = _read_smb_file(conn, "SYSVOL", xml_path)
        if xml_data:
            parsed = parse_groups_xml(xml_data)
            for cat in aggregated:
                aggregated[cat].update(parsed.get(cat, []))
            for pwd in parsed.get("GPPPasswords", []):
                pwd["gpo_guid"] = guid_upper
                all_gpp_passwords.append(pwd)

        # User-side Groups.xml
        user_xml_path = gpo_dir + "\\User\\Preferences\\Groups\\Groups.xml"
        user_xml_data = _read_smb_file(conn, "SYSVOL", user_xml_path)
        if user_xml_data:
            parsed_user = parse_groups_xml(user_xml_data)
            for cat in aggregated:
                aggregated[cat].update(parsed_user.get(cat, []))
            for pwd in parsed_user.get("GPPPasswords", []):
                pwd["gpo_guid"] = guid_upper
                all_gpp_passwords.append(pwd)

        # GptTmpl.inf
        inf_path = gpo_dir + "\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
        inf_data = _read_smb_file(conn, "SYSVOL", inf_path)
        if inf_data:
            parsed_inf = parse_gpttmpl_inf(inf_data)
            for cat in aggregated:
                aggregated[cat].update(parsed_inf.get(cat, []))
            for priv, sids in parsed_inf.get("PrivilegeRights", {}).items():
                all_privilege_rights.setdefault(priv, set()).update(sids)

        # Track which GPO cn-GUIDs actually produced membership changes
        if any(len(aggregated[cat]) > pre_counts[cat] for cat in aggregated):
            guids_with_changes.add(guid_upper)

    def _sid_to_bh(sid):
        type_int = id_to_type_cache.get(sid)
        if type_int is not None:
            label = BH_TYPE_LABEL_MAP.get(type_int, "Unknown")
        else:
            label = "Group" if sid.startswith("S-1-5-32-") else "Unknown"
        return {"ObjectIdentifier": sid, "ObjectType": label}

    gpo_changes = {
        "LocalAdmins": [_sid_to_bh(s) for s in sorted(aggregated["LocalAdmins"])],
        "RemoteDesktopUsers": [_sid_to_bh(s) for s in sorted(aggregated["RemoteDesktopUsers"])],
        "DcomUsers": [_sid_to_bh(s) for s in sorted(aggregated["DcomUsers"])],
        "PSRemoteUsers": [_sid_to_bh(s) for s in sorted(aggregated["PSRemoteUsers"])],
        "AffectedComputers": [],
    }

    privilege_rights = {priv: sorted(sids) for priv, sids in all_privilege_rights.items()}

    return gpo_changes, all_gpp_passwords, privilege_rights, guids_with_changes


def compute_affected_computers(guids_with_changes, raw_ous, raw_computers, id_to_type_cache):
    """
    Find computers in OUs that link GPOs with actual membership changes.

    guids_with_changes: set of cn-GUIDs (no braces, uppercase) that had changes
    raw_ous:  list of raw OU dicts with 'distinguishedName' and 'gPLink'
    raw_computers: list of raw computer dicts with 'distinguishedName' and 'objectSid'
    """
    from impacket.ldap.ldaptypes import LDAP_SID

    if not guids_with_changes or not raw_ous or not raw_computers:
        return []

    _guid_re = re.compile(r'cn=(\{[A-F0-9\-]+\})', re.IGNORECASE)

    # Collect OUs that link any GPO with changes
    affected_ou_dns = set()
    for ou in raw_ous:
        gplink = ou.get("gPLink") or ""
        if isinstance(gplink, list):
            gplink = " ".join(gplink)
        if not gplink:
            continue
        for m in _guid_re.finditer(gplink):
            if m.group(1).strip("{}").upper() in guids_with_changes:
                dn = ou.get("distinguishedName") or ""
                if isinstance(dn, list):
                    dn = dn[0] if dn else ""
                if dn:
                    affected_ou_dns.add(dn.upper())
                break

    if not affected_ou_dns:
        return []

    # Find computers whose DN is under an affected OU (direct or indirect)
    affected = []
    seen = set()
    for comp in raw_computers:
        dn = comp.get("distinguishedName") or ""
        if isinstance(dn, list):
            dn = dn[0] if dn else ""
        dn_upper = dn.upper()
        if not dn_upper:
            continue

        for ou_dn in affected_ou_dns:
            if dn_upper.endswith("," + ou_dn):
                sid_raw = comp.get("objectSid")
                if isinstance(sid_raw, bytes):
                    sid = LDAP_SID(sid_raw).formatCanonical()
                elif isinstance(sid_raw, str) and sid_raw.upper().startswith("S-1-"):
                    sid = sid_raw.upper()
                else:
                    break
                if sid and sid not in seen:
                    seen.add(sid)
                    affected.append({"ObjectIdentifier": sid, "ObjectType": "Computer"})
                break

    return affected
