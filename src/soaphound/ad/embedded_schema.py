"""
Embedded fallback schema GUID map for Active Directory.

These are the standard Microsoft Active Directory schema GUIDs, stable across
all AD installations using the default Microsoft schema. They are used as a
fallback when the schema NC cannot be retrieved from the queried DC, which
typically happens in multi-domain forests where the DC returns an LDAP
referral pointing to another domain for the schema NC.

Sources:
- Microsoft AD schema documentation:
  https://learn.microsoft.com/en-us/windows/win32/adschema/
- Cross-referenced with bloodhound.py:
  https://github.com/dirkjanm/BloodHound.py/blob/master/bloodhound/enumeration/acls.py

These GUIDs are part of the public Microsoft AD schema and are used at runtime
by any AD-querying tool (BloodHound, SharpHound, Soaphound, etc.).
"""

# Object class and attribute GUIDs (schemaIDGUID values)
# Keyed by lDAPDisplayName (lowercase) -> schemaIDGUID (string, lowercase, dashed)
EMBEDDED_OBJECTTYPE_GUID_MAP = {
    # Core object classes
    "user": "bf967aba-0de6-11d0-a285-00aa003049e2",
    "computer": "bf967a86-0de6-11d0-a285-00aa003049e2",
    "group": "bf967a9c-0de6-11d0-a285-00aa003049e2",
    "domain": "19195a5a-6da0-11d0-afd3-00c04fd930c9",
    "domain-dns": "19195a5b-6da0-11d0-afd3-00c04fd930c9",
    "organizational-unit": "bf967aa5-0de6-11d0-a285-00aa003049e2",
    "container": "bf967a8b-0de6-11d0-a285-00aa003049e2",
    "group-policy-container": "f30e3bc2-9ff0-11d1-b603-0000f80367c1",
    "site": "bf967ab3-0de6-11d0-a285-00aa003049e2",

    # Privilege escalation relevant attributes
    "ms-mcs-admpwd": "ea1b7b93-5e48-46d5-bc6c-4df4fda78a35",
    "ms-ds-key-credential-link": "5b47d60f-6090-40b2-9f37-2a4de88f3063",
    "ms-ds-allowed-to-act-on-behalf-of-other-identity": "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79",
    "service-principal-name": "f3a64788-5306-11d1-a9c5-0000f80367c1",
    "member": "bf9679c0-0de6-11d0-a285-00aa003049e2",
    "user-account-control": "bf967a68-0de6-11d0-a285-00aa003049e2",
    "unicode-pwd": "bf9679e1-0de6-11d0-a285-00aa003049e2",
    "user-password": "bf967a6e-0de6-11d0-a285-00aa003049e2",
    "primary-group-id": "bf967a00-0de6-11d0-a285-00aa003049e2",

    # GPO/GPLink
    "gp-link": "f30e3bbe-9ff0-11d1-b603-0000f80367c1",

    # Extended Rights (Control Access Rights) - kept for completeness
    "ds-replication-get-changes": "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "ds-replication-get-changes-all": "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "ds-replication-get-changes-in-filtered-set": "89e95b76-444d-4c62-991a-0facbeda640c",
    "user-force-change-password": "00299570-246d-11d0-a768-00aa006e0529",
    "user-account-restrictions-set": "4c164200-20c0-11d0-a768-00aa006e0529",
}

# Extended Rights mapping. These are CONTROL_ACCESS_RIGHTS, NOT attribute
# schema GUIDs. They live in CN=Extended-Rights,CN=Configuration but are
# stable across all Microsoft forests, so they can be hardcoded.
# Source: https://msdn.microsoft.com/en-us/library/cc223512.aspx
EXTRIGHTS_GUID_MAPPING = {
    "GetChanges": "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "GetChangesAll": "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "GetChangesInFilteredSet": "89e95b76-444d-4c62-991a-0facbeda640c",
    "WriteMember": "bf9679c0-0de6-11d0-a285-00aa003049e2",
    "UserForceChangePassword": "00299570-246d-11d0-a768-00aa006e0529",
    "AllowedToAct": "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79",
    "UserAccountRestrictionsSet": "4c164200-20c0-11d0-a768-00aa006e0529",
    "WriteGPLink": "f30e3bbe-9ff0-11d1-b603-0000f80367c1",
}


# Add key variants without dashes for code that normalizes lookups
# (e.g. "organizational-unit" -> "organizationalunit")
_variants = {}
for _key, _val in list(EMBEDDED_OBJECTTYPE_GUID_MAP.items()):
    _key_no_dash = _key.replace("-", "")
    if _key_no_dash != _key:
        _variants[_key_no_dash] = _val
EMBEDDED_OBJECTTYPE_GUID_MAP.update(_variants)
del _variants, _key, _val, _key_no_dash
