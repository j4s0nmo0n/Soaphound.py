from uuid import UUID
from impacket.ldap.ldaptypes import LDAP_SID
from soaphound.ad.cache_gen import pull_all_ad_objects
from soaphound.ad.adws import ADWSReferralError
import json
import base64

def collect_trusts(ip=None, domain=None, username=None, auth=None, base_dn_override=None, cache_file=None, domain_sid=None):
    """
    Collect all trustedDomain objects from the directory or a cache.
    Automatically add the 'domainsid' field to each trust if domain_sid is provided.
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
        trusts = [t for t in trusts if t.get("distinguishedName") and isinstance(t.get("distinguishedName"), str)]

    # Automatically add domainsid if provided
    if domain_sid is not None:
        for t in trusts:
            t["domainsid"] = domain_sid

    print(f"[INFO] Trusts collected: {len(trusts)}")
    return trusts

# Mapping for trust direction and type to string values expected by BloodHound CE
TRUST_DIRECTION_MAP = {
    0: "Disabled",
    1: "Inbound",
    2: "Outbound",
    3: "Bidirectional"
}

TRUST_TYPE_MAP = {
    0: "ParentChild",  # BloodHound.py sometimes uses 0 for ParentChild
    1: "ParentChild",
    2: "TreeRoot",
    3: "External",
    4: "Forest",
    5: "Realm",
    6: "MIT"
}

def trust_to_bh_output(trust_obj):
    """
    Transform an LDAP trust object to BloodHound 'Trusts' format for domains.json.
    Converts TrustDirection and TrustType to string values expected by BloodHound CE.
    """
    # All known trust flags
    TRUST_FLAGS = {
        'NON_TRANSITIVE': 0x00000001,
        'UPLEVEL_ONLY': 0x00000002,
        'QUARANTINED_DOMAIN': 0x00000004,
        'FOREST_TRANSITIVE': 0x00000008,
        'CROSS_ORGANIZATION': 0x00000010,
        'WITHIN_FOREST': 0x00000020,
        'TREAT_AS_EXTERNAL': 0x00000040,
        'USES_RC4_ENCRYPTION': 0x00000080,
        'PIM_TRUST': 0x00000400,
        'CROSS_ORGANIZATION_NO_TGT_DELEGATION': 0x00000200,
        'CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION': 0x00000800,
    }

    def has_flag(flags, flagname):
        """Return True if the specific flag is set in flags."""
        return (flags & TRUST_FLAGS[flagname]) == TRUST_FLAGS[flagname]

    trusttype = 'Unknown'
    is_transitive = False
    sid_filtering = True

    flags = int(trust_obj.get("trustAttributes", 0) or 0)
    # Logic for determining trust type and its properties
    if has_flag(flags, 'WITHIN_FOREST'):
        trusttype = 'ParentChild'
        is_transitive = True
        sid_filtering = has_flag(flags, 'QUARANTINED_DOMAIN')
    elif has_flag(flags, 'FOREST_TRANSITIVE'):
        trusttype = 'Forest'
        is_transitive = True
        sid_filtering = not has_flag(flags, 'TREAT_AS_EXTERNAL')
    elif has_flag(flags, 'TREAT_AS_EXTERNAL') or has_flag(flags, 'CROSS_ORGANIZATION'):
        trusttype = 'External'
        is_transitive = False
        sid_filtering = True
    else:
        is_transitive = not has_flag(flags, 'NON_TRANSITIVE')

    # Get string representation for TrustType
    trusttype_out = trusttype

    secid_raw = trust_obj.get('securityIdentifier')
    try:
        if secid_raw:
            if isinstance(secid_raw, bytes):
                sid_full = LDAP_SID(secid_raw).formatCanonical()
            elif isinstance(secid_raw, str):
                sid_full = LDAP_SID(base64.b64decode(secid_raw)).formatCanonical()
            else:
                sid_full = str(secid_raw)
        else:
            sid_full = ""
    except Exception:
        sid_full = ""
    
    # Get string representation for TrustDirection
    trust_direction_raw = int(trust_obj.get("trustDirection", 0) or 0)
    trust_direction_out = TRUST_DIRECTION_MAP.get(trust_direction_raw, "Disabled")

    return {
        "TargetDomainName": (trust_obj.get("trustPartner") or trust_obj.get("flatName") or trust_obj.get("name", "")).upper(),
        "TargetDomainSid": sid_full,
        "IsTransitive": is_transitive,
        "TrustDirection": trust_direction_out,
        "TrustType": trusttype_out,
        "SidFilteringEnabled": sid_filtering
    }


# =============================================================================
# Trust audit extension - Sandker's 4 dimensions + risk detection
# =============================================================================
#
# References:
#   - https://www.thehacker.recipes/ad/movement/trusts/
#   - https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/
#   - https://offsec.almond.consulting/trust-no-one_are-one-way-trusts-really-one-way.html
#   - https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/
#   - https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-3-sid-filtering-explained
#
# All 4 dimensions are computed from trustAttributes flags per Sandker's lookup
# tables. Comments cite the exact rules.


# Trust flags (redundant with trust_to_bh_output but kept module-level for reuse)
_TRUST_FLAGS = {
    'NON_TRANSITIVE': 0x00000001,
    'UPLEVEL_ONLY': 0x00000002,
    'QUARANTINED_DOMAIN': 0x00000004,
    'FOREST_TRANSITIVE': 0x00000008,
    'CROSS_ORGANIZATION': 0x00000010,
    'WITHIN_FOREST': 0x00000020,
    'TREAT_AS_EXTERNAL': 0x00000040,
    'USES_RC4_ENCRYPTION': 0x00000080,
    'CROSS_ORGANIZATION_NO_TGT_DELEGATION': 0x00000200,
    'PIM_TRUST': 0x00000400,
    'CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION': 0x00000800,
}


def _has_flag(flags, flagname):
    """Return True if the specific flag is set in flags."""
    return (flags & _TRUST_FLAGS[flagname]) == _TRUST_FLAGS[flagname]


def _decode_flag_names(flags):
    """Return the list of flag names that are set in the given int."""
    return [name for name, bit in _TRUST_FLAGS.items() if (flags & bit) == bit]


def analyze_trust_dimensions(trust_obj):
    """Analyze the 4 security dimensions of a trust from trustAttributes.

    Returns a dict with the 4 Sandker dimensions:
      - transitivity: bool
      - sid_filtering_mode: 'ENABLED' | 'DISABLED' | 'RELAXED'
      - tgt_delegation: 'ENABLED' | 'DISABLED'
      - authentication_level: 'ForestWide' | 'DomainWide' | 'Selective'

    Rules from Sandker (securesystems.de) + Microsoft MS-ADTS 6.1.6.7.9.
    """
    flags = int(trust_obj.get("trustAttributes", 0) or 0)

    # --- Transitivity ---
    # Rule (Sandker):
    #   NON_TRANSITIVE set                          -> False
    #   WITHIN_FOREST or FOREST_TRANSITIVE set      -> True
    #   otherwise                                   -> False
    if _has_flag(flags, 'NON_TRANSITIVE'):
        transitivity = False
    elif _has_flag(flags, 'WITHIN_FOREST') or _has_flag(flags, 'FOREST_TRANSITIVE'):
        transitivity = True
    else:
        transitivity = False

    # --- SID Filtering mode ---
    # Rules (combined Sandker + MS-PAC 4.1.2.2 + Dirk-jan Mollema on relaxation):
    #   QUARANTINED_DOMAIN set                                   -> ENABLED (only trusted domain SIDs)
    #   FOREST_TRANSITIVE set + TREAT_AS_EXTERNAL set            -> RELAXED (RID<1000 filtered, >=1000 accepted)
    #   FOREST_TRANSITIVE set + TREAT_AS_EXTERNAL clear          -> ENABLED (full SID filtering)
    #   TREAT_AS_EXTERNAL set (without FOREST_TRANSITIVE)        -> ENABLED (external trust, RID<1000 filtered only)
    #   WITHIN_FOREST set + QUARANTINED_DOMAIN clear             -> DISABLED (intra-forest default)
    #   otherwise                                                -> ENABLED (safer default)
    if _has_flag(flags, 'QUARANTINED_DOMAIN'):
        sid_filtering_mode = 'ENABLED'
    elif _has_flag(flags, 'FOREST_TRANSITIVE'):
        if _has_flag(flags, 'TREAT_AS_EXTERNAL'):
            sid_filtering_mode = 'RELAXED'
        else:
            sid_filtering_mode = 'ENABLED'
    elif _has_flag(flags, 'WITHIN_FOREST'):
        sid_filtering_mode = 'DISABLED'
    else:
        sid_filtering_mode = 'ENABLED'

    # --- TGT Delegation ---
    # Rules (Sandker):
    #   CROSS_ORGANIZATION_NO_TGT_DELEGATION set     -> DISABLED
    #   QUARANTINED_DOMAIN set                       -> DISABLED
    #   CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION set -> ENABLED
    #   WITHIN_FOREST set                            -> ENABLED
    #   otherwise (external forest trusts)           -> DISABLED (safe default post-CVE-2019-0683)
    if _has_flag(flags, 'CROSS_ORGANIZATION_NO_TGT_DELEGATION'):
        tgt_delegation = 'DISABLED'
    elif _has_flag(flags, 'QUARANTINED_DOMAIN'):
        tgt_delegation = 'DISABLED'
    elif _has_flag(flags, 'CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION'):
        tgt_delegation = 'ENABLED'
    elif _has_flag(flags, 'WITHIN_FOREST'):
        tgt_delegation = 'ENABLED'
    else:
        tgt_delegation = 'DISABLED'

    # --- Authentication level ---
    # Rules (Sandker):
    #   WITHIN_FOREST set                                    -> ForestWide (cannot be disabled)
    #   Cross-forest + CROSS_ORGANIZATION set                -> Selective
    #   Cross-forest + FOREST_TRANSITIVE set (no CROSS_ORG)  -> ForestWide
    #   otherwise                                            -> DomainWide
    if _has_flag(flags, 'WITHIN_FOREST'):
        authentication_level = 'ForestWide'
    elif _has_flag(flags, 'CROSS_ORGANIZATION'):
        authentication_level = 'Selective'
    elif _has_flag(flags, 'FOREST_TRANSITIVE'):
        authentication_level = 'ForestWide'
    else:
        authentication_level = 'DomainWide'

    return {
        'transitivity': transitivity,
        'sid_filtering_mode': sid_filtering_mode,
        'tgt_delegation': tgt_delegation,
        'authentication_level': authentication_level,
        'attributes_flags': _decode_flag_names(flags),
        'raw_attributes': flags,
    }


def detect_trust_risks(trust_obj, dimensions):
    """Detect security risks for a trust based on its dimensions and attributes.

    Returns a list of risk dicts:
        [{'id': str, 'severity': 'HIGH'|'MEDIUM'|'INFO',
          'name': str, 'description': str, 'reference': str}]

    Risks are conservative: they flag configurations that COULD be abused,
    the pentester is expected to validate exploitability.
    """
    flags = int(trust_obj.get("trustAttributes", 0) or 0)
    direction = int(trust_obj.get("trustDirection", 0) or 0)
    risks = []

    # --- TRUST-01: Intra-forest trust (WITHIN_FOREST) ---
    # SID filtering disabled by default in intra-forest trusts, allowing
    # SidHistory injection from child -> forest root compromise.
    if _has_flag(flags, 'WITHIN_FOREST') and not _has_flag(flags, 'QUARANTINED_DOMAIN'):
        risks.append({
            'id': 'TRUST-01',
            'severity': 'HIGH',
            'name': 'Intra-forest trust - SID filtering disabled by default',
            'description': (
                'Trust is within the same forest (WITHIN_FOREST) and QUARANTINED_DOMAIN '
                'is not set. SID filtering is disabled by default in intra-forest trusts. '
                'A compromised child domain can forge tickets with EnterpriseAdmins SID '
                'in SIDHistory and compromise the forest root.'
            ),
            'reference': 'https://blog.harmj0y.net/redteaming/not-a-security-boundary-breaking-forest-trusts/',
        })

    # --- TRUST-02: Forest trust with TREAT_AS_EXTERNAL ---
    # SID filtering relaxed: RID>=1000 accepted, enabling SidHistory injection
    # via privileged groups (e.g. Exchange, custom admin groups).
    if (_has_flag(flags, 'FOREST_TRANSITIVE') and
            _has_flag(flags, 'TREAT_AS_EXTERNAL') and
            not _has_flag(flags, 'QUARANTINED_DOMAIN')):
        risks.append({
            'id': 'TRUST-02',
            'severity': 'HIGH',
            'name': 'Forest trust with SID filtering relaxation (TREAT_AS_EXTERNAL)',
            'description': (
                'Forest trust configured with TREAT_AS_EXTERNAL flag, which relaxes '
                'SID filtering: only RID<1000 are filtered, RID>=1000 are accepted. '
                'An attacker in the trusted forest can inject SIDs of privileged '
                'groups (Exchange, custom admin groups, etc.) via SIDHistory to '
                'escalate in the trusting forest.'
            ),
            'reference': 'https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/',
        })

    # --- TRUST-03: TGT delegation enabled cross-forest ---
    # Allows unconstrained delegation abuse to compromise trusting DC.
    if _has_flag(flags, 'CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION'):
        risks.append({
            'id': 'TRUST-03',
            'severity': 'HIGH',
            'name': 'Cross-forest TGT delegation enabled',
            'description': (
                'CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION flag is set. Kerberos TGT '
                'delegation is enabled across this trust, which allows unconstrained '
                'delegation abuse: an attacker who compromises an account configured '
                'for KUD in the trusted domain can escalate to any resource in the '
                'trusting domain (including DCs).'
            ),
            'reference': 'https://www.thehacker.recipes/ad/movement/trusts/#unconstrained-delegation-abuse',
        })

    # --- TRUST-04: External/Forest trust without SID filtering enforced ---
    # Not as severe as TRUST-01/02 but worth flagging as configuration weakness.
    is_external_or_forest = (
        _has_flag(flags, 'FOREST_TRANSITIVE') or
        _has_flag(flags, 'TREAT_AS_EXTERNAL') or
        _has_flag(flags, 'CROSS_ORGANIZATION')
    )
    if is_external_or_forest and not _has_flag(flags, 'QUARANTINED_DOMAIN'):
        # Skip if already flagged by TRUST-02 (avoid duplicate)
        if not (dimensions['sid_filtering_mode'] == 'RELAXED'):
            risks.append({
                'id': 'TRUST-04',
                'severity': 'MEDIUM',
                'name': 'External/Forest trust without full SID filtering',
                'description': (
                    'Cross-forest or external trust without QUARANTINED_DOMAIN flag. '
                    'SID filtering follows default rules which may allow SIDHistory '
                    'injection in some configurations. Consider enabling '
                    'QUARANTINED_DOMAIN for stricter isolation.'
                ),
                'reference': 'https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-3-sid-filtering-explained',
            })

    # --- TRUST-05: RC4 encryption on trust ---
    # Weak crypto on inter-realm keys.
    if _has_flag(flags, 'USES_RC4_ENCRYPTION'):
        risks.append({
            'id': 'TRUST-05',
            'severity': 'MEDIUM',
            'name': 'Trust uses RC4 encryption',
            'description': (
                'USES_RC4_ENCRYPTION flag is set. Inter-realm Kerberos tickets are '
                'encrypted with RC4-HMAC, which is deprecated and vulnerable to '
                'various attacks. Consider migrating to AES.'
            ),
            'reference': 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c',
        })

    # --- TRUST-06: PIM_TRUST (Bastion Forest) ---
    # Not a vuln per se but requires verification of Shadow Principals.
    if _has_flag(flags, 'PIM_TRUST'):
        risks.append({
            'id': 'TRUST-06',
            'severity': 'INFO',
            'name': 'PIM Trust (Bastion Forest / Red Forest / ESAE)',
            'description': (
                'PIM_TRUST flag is set, indicating this trust connects to a Bastion '
                'Forest (a.k.a. Red Forest / ESAE) used for privileged access '
                'management. Verify the Shadow Principals in '
                '"CN=Shadow Principal Configuration,CN=Services,{ConfigNC}" of the '
                'Bastion forest - a compromise there can grant Domain Admin or '
                'Enterprise Admin in the production forest.'
            ),
            'reference': 'https://www.thehacker.recipes/ad/movement/trusts/#mim-pam-bastion-red-forests',
        })

    # --- TRUST-07: One-way trust (potentially reversible via TDO extraction) ---
    # Article Almond: one-way trusts are not really one-way.
    # Inbound: this domain is trusted by another. TDO on the other side.
    # Outbound: this domain trusts another. TDO on THIS side, potentially extractable.
    if direction in (1, 2):  # 1=Inbound, 2=Outbound (not 3=Bidirectional)
        direction_name = 'Inbound' if direction == 1 else 'Outbound'
        risks.append({
            'id': 'TRUST-07',
            'severity': 'INFO',
            'name': f'One-way trust ({direction_name}) - verify TDO extraction feasibility',
            'description': (
                f'This is a one-way trust (direction: {direction_name}). Per Almond '
                'research, one-way trusts are not truly one-way: the TDO on the '
                'trusting side stores the trust account credentials in cleartext '
                'and as Kerberos keys, which can be extracted with tdo_dump if the '
                'trusting domain is compromised. This effectively reverses the trust '
                'direction, allowing pivot from trusting to trusted domain.'
            ),
            'reference': 'https://offsec.almond.consulting/trust-no-one_are-one-way-trusts-really-one-way.html',
        })

    return risks


def trust_to_audit_output(trust_obj):
    """Enriched output for trust audit reports.

    Extends trust_to_bh_output() with:
      - AttributesFlags: list of trustAttributes flag names that are set
      - AttributesRaw: the raw trustAttributes integer
      - Transitivity: bool (per Sandker's rules)
      - SIDFilteringMode: 'ENABLED' | 'DISABLED' | 'RELAXED'
      - TGTDelegation: 'ENABLED' | 'DISABLED'
      - AuthenticationLevel: 'ForestWide' | 'DomainWide' | 'Selective'
      - AuditRisks: list of risk dicts (see detect_trust_risks)

    All existing BloodHound fields are preserved untouched. BloodHound will
    ignore the extra fields, so this output can also be used for BH input.
    """
    bh = trust_to_bh_output(trust_obj)
    dimensions = analyze_trust_dimensions(trust_obj)
    risks = detect_trust_risks(trust_obj, dimensions)

    bh['AttributesFlags'] = dimensions['attributes_flags']
    bh['AttributesRaw'] = dimensions['raw_attributes']
    bh['Transitivity'] = dimensions['transitivity']
    bh['SIDFilteringMode'] = dimensions['sid_filtering_mode']
    bh['TGTDelegation'] = dimensions['tgt_delegation']
    bh['AuthenticationLevel'] = dimensions['authentication_level']
    bh['AuditRisks'] = risks

    return bh


# =============================================================================
# Forest-wide trust collection
# =============================================================================
#
# collect_forest_trusts() queries each domain NC in the forest for its TDOs
# instead of only the connected domain. This is important because:
#   - A trust has two TDOs (one on each side), and their trustAttributes can
#     technically differ.
#   - An audit that only sees one side would miss half the picture.
#
# Domain NCs are extracted from RootDSE's namingContexts, filtered to exclude
# Configuration, Schema, DomainDnsZones and ForestDnsZones (which are not
# domain partitions).


def _is_domain_naming_context(nc, config_nc, schema_nc):
    """Return True if the given naming context is a domain NC.

    Excludes Configuration, Schema, and *DnsZones NCs (application partitions).
    """
    if not nc:
        return False
    nc_upper = nc.upper()
    # Explicit exclusion of well-known non-domain NCs
    if config_nc and nc_upper == config_nc.upper():
        return False
    if schema_nc and nc_upper == schema_nc.upper():
        return False
    # Exclude application partitions (DomainDnsZones, ForestDnsZones, etc.)
    # Domain NCs start directly with 'DC=' at the top level; app partitions
    # typically have 'DC=DomainDnsZones,DC=...' or 'DC=ForestDnsZones,DC=...'
    if nc_upper.startswith("DC=DOMAINDNSZONES,") or nc_upper.startswith("DC=FORESTDNSZONES,"):
        return False
    if not nc_upper.startswith("DC="):
        return False
    return True


def _nc_to_domain_name(nc):
    """Convert a domain NC like 'DC=modulo,DC=jjk,DC=local' to 'modulo.jjk.local'."""
    if not nc:
        return ""
    parts = [p.strip()[3:] for p in nc.split(",") if p.strip().upper().startswith("DC=")]
    return ".".join(parts).lower()


def collect_forest_trusts(ip, domain, username, auth, naming_contexts,
                          config_nc, schema_nc, domain_sid=None):
    """Collect trustedDomain objects from every domain NC in the forest.

    Args:
        ip, domain, username, auth: standard ADWS connection params
        naming_contexts: list of NCs from RootDSE (contexts['namingContexts'])
        config_nc: configurationNamingContext (for filtering)
        schema_nc: schemaNamingContext (for filtering)
        domain_sid: SID of the connected domain (used as fallback if
                    per-domain SID cannot be determined)

    Returns:
        list of trust dicts, each tagged with 'source_domain_dn' and
        'source_domain_name' indicating which domain the TDO was collected from.

    Behavior:
        - Best-effort: if a domain NC cannot be queried (referral not followed,
          network issue, permissions), it is skipped with a warning logged.
        - The result may include duplicate trust names when viewed from
          different sides (that's the point: both TDOs are shown).
    """
    all_trusts = []

    # Discover all domain NCs in the forest via CN=Partitions,CN=Configuration.
    # This is the authoritative source for forest topology because CN=Partitions
    # is replicated across all DCs and holds a crossRef object for every domain
    # in the forest, including remote ones the queried DC does not host.
    #
    # Fallback to RootDSE's namingContexts if the Partitions query fails (e.g.
    # permission issue or older AD version).
    domain_ncs = []
    if config_nc:
        try:
            partitions_dn = f"CN=Partitions,{config_nc}"
            print(f"[INFO] Discovering forest domains via {partitions_dn}")
            # We bypass pull_all_ad_objects here because crossRef objects don't
            # expose a distinguishedName attribute in their ADWS payload, which
            # trips the filter in pull_all_ad_objects. A direct pull + manual
            # XML parsing gets us the nCName/systemFlags we need. See the XML
            # sample in the design notes: crossRef has <nCName>, <systemFlags>,
            # <dnsRoot>, <name> but no <distinguishedName>.
            from soaphound.ad.adws import ADWSConnect
            from xml.etree import ElementTree as ET
            NS = {
                'addata': "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
                'ad': "http://schemas.microsoft.com/2008/1/ActiveDirectory",
            }
            pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
            et = pull_client.pull(
                query="(objectClass=crossRef)",
                attributes=["nCName", "dnsRoot", "name", "netBIOSName", "systemFlags"],
                base_object_dn_for_soap=partitions_dn,
            )
            if et is not None:
                for cr_elem in et.findall(".//addata:crossRef", namespaces=NS):
                    ncname_elem = cr_elem.find(".//addata:nCName/ad:value", namespaces=NS)
                    sysflags_elem = cr_elem.find(".//addata:systemFlags/ad:value", namespaces=NS)
                    if ncname_elem is None or sysflags_elem is None:
                        continue
                    nc = (ncname_elem.text or "").strip()
                    try:
                        sysflags = int(sysflags_elem.text or 0)
                    except (TypeError, ValueError):
                        sysflags = 0
                    # FLAG_CR_NTDS_DOMAIN = 0x2. crossRefs with this bit are
                    # domain NCs; without it they're application partitions
                    # (DomainDnsZones, ForestDnsZones, etc.).
                    if nc and (sysflags & 0x2) and nc not in domain_ncs:
                        domain_ncs.append(nc)
            print(f"[INFO] Forest domains found via CN=Partitions: {len(domain_ncs)}")
        except Exception as e:
            print(f"[!] CN=Partitions query failed ({e}); falling back to RootDSE namingContexts")

    # Fallback: filter RootDSE namingContexts if CN=Partitions gave nothing
    if not domain_ncs:
        domain_ncs = [nc for nc in (naming_contexts or [])
                      if _is_domain_naming_context(nc, config_nc, schema_nc)]

    if not domain_ncs:
        print("[!] No domain naming contexts discovered; falling back to single-domain collection")
        trusts = collect_trusts(ip, domain, username, auth, domain_sid=domain_sid)
        for t in trusts:
            t['source_domain_dn'] = "DC=" + ",DC=".join(domain.split('.'))
            t['source_domain_name'] = domain.lower()
        return trusts

    print(f"[INFO] Forest discovered: {len(domain_ncs)} domain partition(s)")
    for nc in domain_ncs:
        source_name = _nc_to_domain_name(nc)
        print(f"[INFO] Querying trusts from {source_name} ({nc})")
        try:
            trusts = collect_trusts(
                ip=ip,
                domain=domain,
                username=username,
                auth=auth,
                base_dn_override=f"CN=System,{nc}",
                domain_sid=domain_sid,
            )
        except ADWSReferralError as ref_err:
            # The connected DC does not host this partition. Retry against
            # the DC named in the referral (typically a DC of the target
            # domain). Requires DNS resolution for the referred DC hostname.
            target_dc = ref_err.referral_dc
            if not target_dc:
                print(f"[!]   -> Referral without extractable DC hostname, skipping {source_name}")
                continue
            print(f"[INFO]   -> Referral detected, retrying against {target_dc}")
            try:
                trusts = collect_trusts(
                    ip=target_dc,
                    domain=domain,
                    username=username,
                    auth=auth,
                    base_dn_override=f"CN=System,{nc}",
                    domain_sid=domain_sid,
                )
            except Exception as e2:
                print(f"[!]   -> Retry against {target_dc} also failed: {e2}")
                print(f"[!]      Hint: ensure {target_dc} resolves (check /etc/hosts) "
                      f"and ADWS is reachable there")
                continue
        except Exception as e:
            print(f"[!] Could not collect trusts from {source_name}: {e}")
            continue

        for t in trusts:
            t['source_domain_dn'] = nc
            t['source_domain_name'] = source_name
        all_trusts.extend(trusts)
        print(f"[INFO]   -> {len(trusts)} trust(s) collected from {source_name}")

    print(f"[INFO] Total trusts collected across forest: {len(all_trusts)}")
    return all_trusts
