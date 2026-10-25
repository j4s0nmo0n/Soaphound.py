import datetime
import logging
import socket
from base64 import b64decode
from enum import IntFlag
from typing import Self, Type  # Self is for Python 3.11+
from uuid import UUID, uuid4
from xml.etree import ElementTree

from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE,
    ACCESS_ALLOWED_CALLBACK_ACE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
    ACCESS_ALLOWED_OBJECT_ACE,
    LDAP_SID,
    SR_SECURITY_DESCRIPTOR,
    SYSTEM_MANDATORY_LABEL_ACE,
)
from pyasn1.type.useful import GeneralizedTime

import soaphound.ad.ms_nmf as ms_nmf
from .ms_nns import NNS
from .soap_templates import (
    LDAP_PULL_FSTRING,
    LDAP_PUT_FSTRING,
    LDAP_QUERY_FSTRING,
    NAMESPACES,
    LDAP_ROOT_DSE_FSTRING,
    TM_GET_AD_FOREST_FSTRING,
    TM_TRANSLATE_NAME_FSTRING,
    TM_CHANGE_OPTIONAL_FEATURE_FSTRING,
    TM_GET_VERSION_FSTRING,
    TM_GET_AD_DOMAIN_FSTRING,
    TM_GET_AD_DOMAIN_CONTROLLER_FSTRING,
)

# MS-ADCAP ActiveDirectoryNameFormat enum (per [MS-ADCAP] Appendix A). Only
# two values are defined by the contract -- the Win32 LSA EXTENDED_NAME_FORMAT
# constants (NameFullyQualifiedDN=1, NameSamCompatible=2, etc.) are a
# distinct enumeration and MUST NOT be mixed with this one. The ser:
# EnumerationValue int in the WSDL annotation is kept here for traceability.
_AD_NAME_FORMAT_NAMES: dict[int, str] = {
    1: "DistinguishedName",
    2: "CanonicalName",
}


# Multi-valued fields in the MS-ADCAP ``GetADForest`` response. The server
# wraps their items in <ser:string> children, and empty collections may come
# back either as an empty wrapper (``<Sites/>``) or as ``xsi:nil="true"``.
# Both must normalise to ``[]`` so JSON consumers can iterate without a
# per-field null check. Both PascalCase variants are listed because the
# live server uses ``UPNSuffixes``/``SPNSuffixes`` while some docs/tests
# use ``UpnSuffixes``/``SpnSuffixes``.
_FOREST_ARRAY_FIELDS: frozenset = frozenset({
    "ApplicationPartitions",
    "CrossForestReferences",
    "Domains",
    "GlobalCatalogs",
    "Sites",
    "UPNSuffixes", "UpnSuffixes",
    "SPNSuffixes", "SpnSuffixes",
})


def _localname_from_tag(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _parse_ad_forest_payload(payload) -> dict:
    """Parse a GetADForest response payload into a structured dict.

    Match children by local name only, ignoring namespaces, because the
    server mixes several namespace prefixes in the response (CustomActions
    for the field names, Serialization/Arrays for ``<string>`` items,
    XMLSchema-instance for ``nil``). This mirrors SOAPy's regex-based
    approach (SOAPy ``src/adcap.py`` ``get_ad_forest``).
    """
    return _parse_wrapped_payload(payload, ("Forest", "GetADForestResult"), _FOREST_ARRAY_FIELDS)


# Multi-valued fields in the MS-ADCAP ``GetADDomain`` response (observed
# empirically on Windows Server 2025: live server uses ``AllowedDNSSuffixes``,
# etc.). Same normalisation rule as the forest fields: nil or empty wrapper
# collapses to [].
_DOMAIN_ARRAY_FIELDS: frozenset = frozenset({
    "AllowedDNSSuffixes",
    "AppliedGroupPolicies",
    "ChildDomains",
    "ObjectTypes",
    "ReadOnlyReplicaDirectoryServer",
    "ReplicaDirectoryServer",
    "SubordinateReferences",
})


def _is_nil(elem) -> bool:
    """True if the element carries any ``nil="true"`` attribute (any
    namespace: ``i:nil``, ``xsi:nil``, …)."""
    for k, v in elem.attrib.items():
        if _localname_from_tag(k) == "nil" and v == "true":
            return True
    return False


def _parse_wrapped_payload(payload, wrapper_names: tuple, array_fields: frozenset) -> dict:
    """Generic ADCAP parser for a response shaped like
    ``<Response><Wrapper>...fields...</Wrapper></Response>``.

    Descends into whichever ``wrapper_names`` element appears first,
    falling back to the payload's own children. For each child:
      - ``nil="true"`` → ``[]`` if the local name is in ``array_fields``,
        else ``None``;
      - any ``<string>`` descendant → list of their text() values;
      - local name in ``array_fields`` but no ``<string>`` child → ``[]``;
      - plain text → str (stripped), or ``None`` when empty.
    """
    def _localname(elem):
        return _localname_from_tag(elem.tag)

    wrapper = None
    for descendant in payload.iter():
        if _localname(descendant) in wrapper_names:
            wrapper = descendant
            break
    if wrapper is None:
        wrapper = payload

    out: dict = {}
    for child in wrapper:
        tag = _localname(child)
        if _is_nil(child):
            out[tag] = [] if tag in array_fields else None
            continue
        string_children = [sub for sub in child.iter() if _localname(sub) == "string"]
        if string_children:
            out[tag] = [sub.text for sub in string_children if sub.text]
            continue
        if tag in array_fields:
            out[tag] = []
            continue
        text = (child.text or "").strip() if child.text else ""
        out[tag] = text if text else None
    return out


def _parse_ad_domain_payload(payload) -> dict:
    """Parse a GetADDomain response payload (shape mirrors GetADForest with
    a ``<Domain>`` wrapper instead of ``<Forest>``)."""
    return _parse_wrapped_payload(payload, ("Domain", "GetADDomainResult"), _DOMAIN_ARRAY_FIELDS)


def _parse_dc_payload(payload) -> dict:
    """Parse a GetADDomainController response payload into a structured dict.

    The server wraps results in ``<DomainControllers>`` (plural) containing
    one or more ``<ActiveDirectoryDomainController>`` entries — the latter is
    the field-bearing wrapper. It carries scalars, ``<string>`` arrays
    (``<Partitions>``) and nested typed-element arrays
    (``<OperationMasterRole>`` wraps repeated
    ``<ActiveDirectoryOperationMasterRole>`` children — flattened to a list
    of their text() values). Only the first ``<ActiveDirectoryDomainController>``
    is returned; callers that need multi-DC results should iterate the
    response themselves.
    """
    def _localname(elem):
        return _localname_from_tag(elem.tag)

    wrapper = None
    for descendant in payload.iter():
        if _localname(descendant) == "ActiveDirectoryDomainController":
            wrapper = descendant
            break
    if wrapper is None:
        wrapper = payload

    out: dict = {}
    for child in wrapper:
        tag = _localname(child)

        if _is_nil(child):
            out[tag] = None
            continue

        string_children = [sub for sub in child.iter() if _localname(sub) == "string"]
        if string_children:
            out[tag] = [sub.text for sub in string_children if sub.text]
            continue

        # Nested typed-element array (e.g. OperationMasterRole wrapping
        # repeated ActiveDirectoryOperationMasterRole items). Any direct
        # child element with text() is treated as a list item.
        direct_children = list(child)
        if direct_children:
            out[tag] = [sub.text for sub in direct_children if sub.text]
            continue

        text = (child.text or "").strip() if child.text else ""
        out[tag] = text if text else None

    return out


def _decode_binary_sid_b64(value: str) -> str:
    """Decode a base64-encoded binary SID (``xs:base64Binary``) to its
    canonical ``S-1-5-…`` form. The server ships ``DomainSID`` this way.

    Returns the input unchanged on decode failure so fixtures carrying a
    pre-decoded dotted SID (and any future server that already decodes
    server-side) pass through untouched.
    """
    if not value:
        return value
    try:
        from base64 import b64decode
        from impacket.ldap.ldaptypes import LDAP_SID
        return LDAP_SID(b64decode(value)).formatCanonical()
    except Exception:
        return value


def _ad_name_format_name(value: "int | str") -> str:
    """Convert a MS-ADCAP ``ActiveDirectoryNameFormat`` value to the
    PascalCase enum member name expected by the ADWS AccountManagement
    endpoint (as declared in [MS-ADCAP] Appendix A).

    Only ``1 -> "DistinguishedName"`` and ``2 -> "CanonicalName"`` are
    defined by the contract. The richer EXTENDED_NAME_FORMAT values
    (SAM / Display / UPN / SPN / UniqueId / etc. -- used by Win32
    ``TranslateName`` through NTDSAPI/DRSR) are **not** part of
    MS-ADCAP and raise ValueError here. Strings are passed through so
    callers may supply the member name directly.
    """
    if isinstance(value, str):
        return value
    try:
        return _AD_NAME_FORMAT_NAMES[value]
    except KeyError as exc:
        raise ValueError(
            f"Unknown ActiveDirectoryNameFormat value {value}; "
            f"MS-ADCAP only defines {sorted(_AD_NAME_FORMAT_NAMES)}. "
            f"Richer EXTENDED_NAME_FORMAT values are not supported by this contract."
        ) from exc


# --- Enums and Constants ---
class SystemFlags(IntFlag):
    NONE = 0x00000000
    NO_REPLICATION = 0x00000001
    REPLICATE_TO_GC = 0x00000002
    CONSTRUCTED = 0x00000004
    CATEGORY_1 = 0x00000010
    NOT_DELETED = 0x02000000
    CANNOT_MOVE = 0x04000000
    CANNOT_RENAME = 0x08000000
    MOVED_WITH_RESTRICTIONS = 0x10000000
    MOVED = 0x20000000
    RENAMED = 0x40000000
    CANNOT_DELETE = 0x80000000

class InstanceTypeFlags(IntFlag):
    HEAD_OF_NAMING_CONTEXT = 0x00000001
    REPLICA_NOT_INSTANTIATED = 0x00000002
    OBJECT_WRITABLE = 0x00000004
    NAMING_CONTEXT_HELD = 0x00000008
    CONSTRUCTING_NAMING_CONTEXT = 0x00000010
    REMOVING_NAMING_CONTEXT = 0x00000020

class GroupTypeFlags(IntFlag):
    SYSTEM_GROUP = 0x00000001
    GLOBAL_SCOPE = 0x00000002
    DOMAIN_LOCAL_SCOPE = 0x00000004
    UNIVERSAL_SCOPE = 0x00000008
    APP_BASIC_GROUP = 0x00000010
    APP_QUERY_GROUP = 0x00000020
    SECURITY_GROUP = 0x80000000

class AccountPropertyFlag(IntFlag):
    SCRIPT = 0x0001
    ACCOUNTDISABLE = 0x0002
    HOMEDIR_REQUIRED = 0x0008
    LOCKOUT = 0x0010
    PASSWD_NOTREQD = 0x0020
    PASSWD_CANT_CHANGE = 0x0040
    ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
    TEMP_DUPLICATE_ACCOUNT = 0x0100
    NORMAL_ACCOUNT = 0x0200
    INTERDOMAIN_TRUST_ACCOUNT = 0x0800
    WORKSTATION_TRUST_ACCOUNT = 0x1000
    SERVER_TRUST_ACCOUNT = 0x2000
    DONT_EXPIRE_PASSWORD = 0x10000
    MNS_LOGON_ACCOUNT = 0x20000
    SMARTCARD_REQUIRED = 0x40000
    TRUSTED_FOR_DELEGATION = 0x80000
    NOT_DELEGATED = 0x100000
    USE_DES_KEY_ONLY = 0x200000
    DONT_REQ_PREAUTH = 0x400000
    PASSWORD_EXPIRED = 0x800000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
    PARTIAL_SECRETS_ACCOUNT = 0x04000000

class SamAccountType(IntFlag):
    SAM_DOMAIN_OBJECT = 0x00000000
    SAM_GROUP_OBJECT = 0x10000000
    SAM_NON_SECURITY_GROUP_OBJECT = 0x10000001
    SAM_ALIAS_OBJECT = 0x20000000
    SAM_NON_SECURITY_ALIAS_OBJECT = 0x20000001
    SAM_USER_OBJECT = 0x30000000
    SAM_MACHINE_ACCOUNT = 0x30000001
    SAM_TRUST_ACCOUNT = 0x30000002
    SAM_APP_BASIC_GROUP = 0x40000000
    SAM_APP_QUERY_GROUP = 0x40000001

BUILT_IN_GROUPS = {
    "498": "Enterprise Read-Only Domain Controllers", "512": "Domain Admins",
    "513": "Domain Users", "514": "Domain Guests", "515": "Domain Computers",
    "516": "Domain Controllers", "517": "Cert Publishers", "518": "Schema Admins",
    "519": "Enterprise Admins", "520": "Group Policy Creator Owners",
    "521": "Read-Only Domain Controllers", "522": "Cloneable Controllers",
    "525": "Protected Users", "526": "Key Admins", "527": "Enterprise Key Admins",
    "553": "RAS and IAS Servers", "571": "Allowed RODC Password Replication Group",
    "572": "Denied RODC Password Replication Group",
}
WELL_KNOWN_SIDS = {
    "S-1-0": "Null Authority", "S-1-0-0": "Nobody", "S-1-1": "World Authority", "S-1-1-0": "Everyone",
    "S-1-2": "Local Authority", "S-1-2-0": "Local", "S-1-2-1": "Console Logon",
    "S-1-3": "Creator Authority", "S-1-3-0": "Creator Owner", "S-1-3-1": "Creator Group",
    "S-1-3-2": "Creator Owner Server", "S-1-3-3": "Creator Group Server", "S-1-3-4": "Owner Rights",
    "S-1-5-80-0": "All Services", "S-1-4": "Non-unique Authority", "S-1-5": "NT Authority",
    "S-1-5-1": "Dialup", "S-1-5-2": "Network", "S-1-5-3": "Batch", "S-1-5-4": "Interactive",
    "S-1-5-6": "Service", "S-1-5-7": "Anonymous", "S-1-5-8": "Proxy",
    "S-1-5-9": "Enterprise Domain Controllers", "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users", "S-1-5-12": "Restricted Code", "S-1-5-13": "Terminal Server Users",
    "S-1-5-14": "Remote Interactive Logon", "S-1-5-15": "This Organization", "S-1-5-17": "This Organization",
    "S-1-5-18": "Local System", "S-1-5-19": "NT Authority", "S-1-5-20": "NT Authority",
    "S-1-5-32-544": "Administrators", "S-1-5-32-545": "Users", "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users", "S-1-5-32-548": "Account Operators", "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators", "S-1-5-32-551": "Backup Operators", "S-1-5-32-552": "Replicators",
    "S-1-5-64-10": "NTLM Authentication", "S-1-5-64-14": "SChannel Authentication", "S-1-5-64-21": "Digest Authority",
    "S-1-5-80": "NT Service", "S-1-5-83-0": "NT VIRTUAL MACHINE\\Virtual Machines",
    "S-1-16-0": "Untrusted Mandatory Level", "S-1-16-4096": "Low Mandatory Level",
    "S-1-16-8192": "Medium Mandatory Level", "S-1-16-8448": "Medium Plus Mandatory Level",
    "S-1-16-12288": "High Mandatory Level", "S-1-16-16384": "System Mandatory Level",
    "S-1-16-20480": "Protected Process Mandatory Level", "S-1-16-28672": "Secure Process Mandatory Level",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access", "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders", "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-558": "BUILTIN\\Performance Monitor Users", "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group", "S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users", "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers", "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
    "S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers", "S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
    "S-1-5-32-577": "BUILTIN\\RDS Management Servers", "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
    "S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators", "S-1-5-32-580": "BUILTIN\\Remote Management Users",
}

class ADWSError(Exception): 
     """Base exception for ADWS errors"""
     pass

class ADWSReferralError(ADWSError):
    """Exception raised when AD returns a referral"""
    def __init__(self, referral_url: str, message: str = ""):
        self.referral_url = referral_url
        self.referral_dc = self._extract_dc_from_url(referral_url)
        super().__init__(f"AD Referral: {message} -> {referral_url}")
    
    @staticmethod
    def _extract_dc_from_url(url: str) -> str:
        """
        Extract DC hostname from LDAP referral URL
        Example: ldap://sub.tld/CN=Schema,... -> sub.tld
        """
        import re
        match = re.search(r'ldap://([^/]+)', url)
        return match.group(1) if match else ""

class ADWSAuthType: ...

class NTLMAuth(ADWSAuthType):
    def __init__(self, password: str | None = None, hashes: str | None = None):
        if not (password or hashes):
            raise ValueError("NTLM auth requires either a password or hashes.")
        if password and hashes:
            raise ValueError("Provide either a password or hashes, not both.")
        self.nt = hashes if hashes else None
        self.password = password

class KerberosAuth(ADWSAuthType):
    """
    Authentification Kerberos via le cache d'identifiants KRB5CCNAME.
    The ticket (TGT or LDAP TGS) must be present in the ccache pointed to by
    la variable d'environnement KRB5CCNAME.
    """
    def __init__(self, kdc_host: str | None = None):
        # KDC host to query for an LDAP TGS if only a TGT
        # is present in the cache. If None, fall back on the target FQDN.
        self.kdc_host = kdc_host

class ADWSConnect:
    def __init__(self, fqdn: str, domain: str, username: str, auth: ADWSAuthType, resource: str ):
        self._fqdn = fqdn
        self._domain = domain
        self._username = username
        self._auth = auth
        self._resource: str = resource
        self._nmf: ms_nmf.NMFConnection = self._connect(self._fqdn, self._resource)

    def _create_NNS_from_auth(self, sock: socket.socket) -> NNS:
        # Authentification NTLM (mot de passe ou hash NT)
        if isinstance(self._auth, NTLMAuth):
            return NNS(socket=sock, fqdn=self._fqdn, domain=self._domain, username=self._username,
                       password=self._auth.password, nt=self._auth.nt if self._auth.nt else "")
        # Authentification Kerberos via ccache (KRB5CCNAME)
        if isinstance(self._auth, KerberosAuth):
            return NNS(
                socket=sock,
                fqdn=self._fqdn,
                domain=self._domain,
                username=self._username,
                auth_protocol="kerberos",
                kdc_host=self._auth.kdc_host,
            )
        raise NotImplementedError("Authentication type not supported")

    def _connect(self, remoteName: str, resource: str) -> ms_nmf.NMFConnection:
        server_address: tuple[str, int] = (remoteName, 9389)
        logging.debug(f"Connecting to {remoteName}:{server_address[1]} for ADWS {self._resource} endpoint")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(server_address)
        except Exception as e:
            logging.error(f"Failed to connect to {remoteName}:{server_address[1]}: {e}")
            raise ADWSError(f"Connection failed: {e}")

        nmf = ms_nmf.NMFConnection(self._create_NNS_from_auth(sock), fqdn=remoteName)
        try:
            nmf.connect(f"Windows/{resource}")
        except Exception as e:
            logging.error(f"NMF connection to resource 'Windows/{resource}' failed: {e}")
            sock.close()
            raise ADWSError(f"NMF connection failed: {e}")
        return nmf

    def get_root_domain_dn(self, fqdn: str) -> str:
        """
        Transforms an FQDN (e.g., sub1.sub.tld) into the root domain DN (e.g., DC=sub,DC=tld)
        """
        parts = fqdn.split('.')
        root = parts[-2:]
        dn = ','.join(f"DC={p}" for p in root)
        return dn

    def _query_enumeration(
        self, remoteName: str, nmf: ms_nmf.NMFConnection, query: str, attributes: list,
        base_object_dn_for_soap: str | None = None, use_schema=False, schema_dn: str | None = None
    ) -> str | None:
        fAttributes: str = "".join([f"<ad:SelectionProperty>addata:{attr}</ad:SelectionProperty>\n" for attr in attributes])

        if use_schema:
            if schema_dn is not None:
                effective_base_obj = schema_dn
            else:
                forest_dn = self.get_root_domain_dn(self._domain)
                effective_base_obj = f"CN=Schema,CN=Configuration,{forest_dn}"
        else:
            effective_base_obj = base_object_dn_for_soap if base_object_dn_for_soap else ",".join([f"DC={i}" for i in self._domain.split(".")])

        query_vars = {
            "uuid": str(uuid4()), "fqdn": remoteName, "query": query,
            "attributes": fAttributes, "baseobj": effective_base_obj,
        }
        enumeration_request_soap = LDAP_QUERY_FSTRING.format(**query_vars)

        nmf.send(enumeration_request_soap)
        enumerationResponse = nmf.recv()

        et = self._handle_str_to_xml(enumerationResponse)
        if et is None:
            logging.error("Failed to parse XML from enumeration response.")
            return None

        enum_ctx_elem = et.find(".//wsen:EnumerationContext", NAMESPACES)
        if enum_ctx_elem is None or enum_ctx_elem.text is None:
            logging.error("No EnumerationContext found in the server response.")
            if enumerationResponse and len(enumerationResponse) < 1000:
                logging.debug(f"Full Enumeration Response without context: {enumerationResponse}")
            return None
        return enum_ctx_elem.text

    def get_schema_naming_context(self, remoteName: str, nmf: ms_nmf.NMFConnection) -> str:
        from xml.etree import ElementTree as ET
        from uuid import uuid4

        req = {
            "uuid": str(uuid4()),
            "fqdn": remoteName,
        }
        soap_request = LDAP_ROOT_DSE_FSTRING.format(**req)

        nmf.send(soap_request)
        response = nmf.recv()

        try:
            et = ET.fromstring(response)
        except Exception as e:
            raise RuntimeError(f"Error parsing RootDSE: {e}\nRaw response: {response[:500]}")

        NAMESPACES = {
            'addata': "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
            'ad': "http://schemas.microsoft.com/2008/1/ActiveDirectory",
        }

        # Look for schemaNamingContext in the XML
        val_elem = et.find(".//addata:schemaNamingContext/ad:value", namespaces=NAMESPACES)
        if val_elem is not None and val_elem.text:
            return val_elem.text.strip()

        # Fallback: look in namingContexts
        for alt_val in et.findall(".//addata:namingContexts/ad:value", namespaces=NAMESPACES):
            if alt_val is not None and alt_val.text and "Schema" in alt_val.text:
                return alt_val.text.strip()

        raise RuntimeError(
            f"schemaNamingContext not found in RootDSE. Raw response:\n{response[:1000]}"
        )

    def get_rootdse_contexts(self, remoteName: str, nmf: ms_nmf.NMFConnection) -> dict:
        """
        Gets key contexts from RootDSE in a single Resource request.
        Returns a dict with fields:
        - schemaNamingContext
        - rootDomainNamingContext
        - configurationNamingContext
        - defaultNamingContext
        - namingContexts (list)
        All values are strings (or list of strings for namingContexts).
        """
        from xml.etree import ElementTree as ET
        from uuid import uuid4

        req = {
            "uuid": str(uuid4()),
            "fqdn": remoteName,
        }
        soap_request = LDAP_ROOT_DSE_FSTRING.format(**req)

        nmf.send(soap_request)
        response = nmf.recv()

        try:
            et = ET.fromstring(response)
        except Exception as e:
            raise RuntimeError(f"Error parsing RootDSE: {e}\nRaw response: {response[:500]}")

        NAMESPACES = {
            'addata': "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
            'ad': "http://schemas.microsoft.com/2008/1/ActiveDirectory",
        }

        def getval(xpath):
            val_elem = et.find(xpath, namespaces=NAMESPACES)
            return val_elem.text.strip() if val_elem is not None and val_elem.text else None

        def getvals(xpath):
            return [
                v.text.strip()
                for v in et.findall(xpath, namespaces=NAMESPACES)
                if v is not None and v.text
            ]

        return {
            "schemaNamingContext": getval(".//addata:schemaNamingContext/ad:value"),
            "rootDomainNamingContext": getval(".//addata:rootDomainNamingContext/ad:value"),
            "configurationNamingContext": getval(".//addata:configurationNamingContext/ad:value"),
            "defaultNamingContext": getval(".//addata:defaultNamingContext/ad:value"),
            "namingContexts": getvals(".//addata:namingContexts/ad:value"),
            "domainFunctionality": getvals(".//addata:domainFunctionality/ad:value"),
            "forestFunctionality": getval(".//addata:forestFunctionality/ad:value")
        }

    def _pull_results(self, remoteName: str, nmf: ms_nmf.NMFConnection, enum_ctx: str) -> tuple[ElementTree.Element | None, bool]:
        pull_vars = {"uuid": str(uuid4()), "fqdn": remoteName, "enum_ctx": enum_ctx}
        pull_request_soap = LDAP_PULL_FSTRING.format(**pull_vars)

        nmf.send(pull_request_soap)
        pullResponse = nmf.recv()

        et = self._handle_str_to_xml(pullResponse)
        if et is None:
            logging.error(f"Failed to parse XML from pull response for context: {enum_ctx}")
            return (None, False)

        final_pkt = et.find(".//wsen:EndOfSequence", namespaces=NAMESPACES)
        return (et, final_pkt is None)  # True if more results (EndOfSequence NOT found)

    def _handle_str_to_xml(self, xmlstr: str) -> ElementTree.Element | None:
        if not xmlstr:
            logging.error("Received empty XML string from server.")
            return None
        
        original_length = len(xmlstr)
        logging.debug(f"Processing XML response ({original_length} bytes)")
        
        # 1. Clean invalid characters
        xmlstr = xmlstr.strip().replace('\x00', '')
        xmlstr = ''.join(c for c in xmlstr if ord(c) >= 32 or c in '\t\n\r')
        
        cleaned_length = len(xmlstr)
        if cleaned_length != original_length:
            removed = original_length - cleaned_length
            logging.debug(f"Cleaned XML: removed {removed} invalid characters")
        
        # 2. Check envelope integrity
        if '</s:Envelope>' not in xmlstr:
            logging.error("XML truncated - missing closing </s:Envelope>")
            logging.debug(f"Last 200 chars of truncated XML: {repr(xmlstr[-200:])}")
            return None
        
        # 3. Truncate garbage after </s:Envelope>
        first_close = xmlstr.find('</s:Envelope>') + len('</s:Envelope>')
        if first_close < len(xmlstr):
            garbage_size = len(xmlstr) - first_close
            logging.warning(f"Truncating {garbage_size} bytes after envelope")
            logging.debug(f"Garbage preview: {repr(xmlstr[first_close:first_close+100])}")
            xmlstr = xmlstr[:first_close]
        
        # 4. Quick Fault detection before full parsing
        has_fault = ":Fault>" in xmlstr and ":Reason>" in xmlstr
        
        # 5. Parsing attempt
        try:
            et = ElementTree.fromstring(xmlstr)
            logging.debug("XML parsed successfully")
        except ElementTree.ParseError as e:
            error_str = str(e)
            logging.error(f"XML ParseError: {error_str}")
            
            # Extract error position
            col = 0
            if 'column' in error_str:
                try:
                    col = int(error_str.split('column ')[-1].split()[0])
                    logging.debug(f"Error at column {col}")
                except:
                    pass
            
            # Context around error (±100 characters)
            snippet_start = max(0, col - 100)
            snippet_end = min(len(xmlstr), col + 100)
            snippet = xmlstr[snippet_start:snippet_end]
            logging.error(f"Error context (column {col}): {repr(snippet)}")
            
            # In debug mode, save problematic XML
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                debug_file = f"failed_xml_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
                try:
                    with open(debug_file, 'w', encoding='utf-8') as f:
                        f.write(xmlstr)
                    logging.debug(f"Failed XML saved to: {debug_file}")
                except Exception as save_err:
                    logging.debug(f"Could not save failed XML: {save_err}")
            
            # If it's a Fault, attempt manual extraction
            if has_fault:
                fault_msg = self._manually_extract_fault(xmlstr)
                logging.error(f"Extracted SOAP Fault: {fault_msg}")
                raise ADWSError(f"SOAP Fault: {fault_msg}")
            
            # Otherwise return None to continue enumeration
            return None
        
        # 6. Check SOAP Fault in parsed XML
        fault_node_s = et.find(f".//{{{NAMESPACES['s']}}}Fault")
        fault_node_soapenv = et.find(f".//{{{NAMESPACES['soapenv']}}}Fault")
        fault_node = fault_node_s if fault_node_s is not None else fault_node_soapenv
        
        if fault_node is not None:
            logging.debug("SOAP Fault detected in parsed XML")
            
            # Extract fault reason
            reason_text_s = fault_node.findtext(f".//{{{NAMESPACES['s']}}}Reason/{{{NAMESPACES['s']}}}Text")
            reason_text_soapenv = fault_node.findtext(f".//{{{NAMESPACES['soapenv']}}}Reason/{{{NAMESPACES['soapenv']}}}Text")
            reason = reason_text_s or reason_text_soapenv or "Unknown SOAP Fault reason"
            
            # Extract fault detail
            detail_node_s = fault_node.find(f".//{{{NAMESPACES['s']}}}Detail")
            detail_node_soapenv = fault_node.find(f".//{{{NAMESPACES['soapenv']}}}Detail")
            detail_node = detail_node_s if detail_node_s is not None else detail_node_soapenv
            
            # Check if this is a referral (error code 8235)
            if detail_node is not None:
                try:
                    win32_error = detail_node.findtext(".//{http://schemas.microsoft.com/2008/1/ActiveDirectory}Win32ErrorCode")
                    referral_url = detail_node.findtext(".//{http://schemas.microsoft.com/2008/1/ActiveDirectory}Referral")
                    
                    if win32_error == "8235" and referral_url:
                        logging.warning(f"AD Referral detected: {referral_url}")
                        raise ADWSReferralError(referral_url, reason)
                except ADWSReferralError:
                    raise  # Re-raise referral errors
                except Exception as e:
                    logging.debug(f"Error parsing fault detail for referral: {e}")
            
            # For other faults, raise standard error
            detail_text = ElementTree.tostring(detail_node, encoding='unicode').strip() if detail_node is not None else "No detail"
            logging.error(f"SOAP Fault received: {reason}")
            logging.debug(f"Fault detail: {detail_text}")
            raise ADWSError(f"{reason}\nDetail: {detail_text}")
        
        return et
    def _manually_extract_fault(self, xml_str: str) -> str:
        """Manual extraction of Fault message when XML doesn't parse"""
        import re
        
        # Search for text between :Text tags
        match = re.search(r':Text[^>]*>([^<]+)<', xml_str)
        if match:
            return match.group(1).strip()
        
        # Fallback: search for anything after :Text
        start = xml_str.find(":Text")
        if start != -1:
            start += len(":Text")
            # Skip opening '>'
            while start < len(xml_str) and xml_str[start] in '> \n\r\t':
                start += 1
            end = xml_str.find("</", start)
            if end != -1:
                return xml_str[start:end].strip()
        
        return "Could not extract fault message"

    def _get_tag_name(self, elem: ElementTree.Element) -> str:
        return elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag

    def _format_flags(self, value_str: str, intflag_class: Type[IntFlag]) -> str:
        try:
            value = int(value_str)
            flags = [flag.name for flag in intflag_class if flag.value & value]
            return f"{value} ({', '.join(flags)})" if flags else str(value)
        except ValueError:
            return str(value_str)

    def _pretty_print_response(self, et: ElementTree.Element, print_synthetic_vars: bool = False) -> None:
        if et is None:
            return
        items_container = et.find(".//wsen:Items", NAMESPACES)
        if items_container is not None:
            for item in items_container:
                dn_elem = item.find(".//addata:distinguishedName/ad:value", NAMESPACES)
                dn = dn_elem.text if dn_elem is not None else "Unknown DN"

    # XML Schema simple types accepted by the ADWS Resource endpoint for the
    # xsi:type attribute on <ad:value>. Values outside this set either produce
    # a malformed SOAP payload or get rejected server-side with
    # AttributeTypeNotValidForEntry.
    _PUT_ALLOWED_DATA_TYPES = frozenset({
        "string", "boolean", "int", "integer", "long",
        "dateTime", "base64Binary", "hexBinary",
    })

    def put(self, object_ref: str, operation: str, attribute: str, data_type: str, value: str) -> bool:
        """Write an attribute on an AD object via the ADWS Resource endpoint
        (WS-Transfer Put).

        Args:
            object_ref: Distinguished Name of the target object.
            operation: One of 'replace', 'add', 'delete' (lowercase, per MS-ADDM
                section 3.1.4.1.4.1).
            attribute: LDAP display name of the attribute to modify (e.g.
                'description', 'servicePrincipalName').
            data_type: XML Schema simple type name WITHOUT the 'xsd:' prefix:
                'string', 'boolean', 'int', 'dateTime', 'base64Binary', etc.
                The template adds the 'xsd:' prefix automatically.
            value: String form of the value to write.

        Returns:
            True on success (empty <Body> or <wxf:PutResponse> in reply),
            False otherwise.

        Raises:
            ValueError: when ``data_type`` is not one of the supported XSD
                simple types (see ``_PUT_ALLOWED_DATA_TYPES``).
            NotImplementedError: when called on a non-Resource client.

        Example:
            auth = NTLMAuth(password="...")
            client = ADWSConnect.put_client(ip, domain, username, auth)
            ok = client.put(
                object_ref="CN=canary,OU=Users,DC=example,DC=local",
                operation="replace",
                attribute="description",
                data_type="string",      # NOT "xsd:string"
                value="updated by soaphound",
            )
        """
        if self._resource != "Resource":
            raise NotImplementedError("Put is only supported on 'put' (Resource) clients")

        # Normalise data_type: strip a legacy 'xsd:' prefix (callers sometimes
        # pass it because that is how the type appears on the wire), then
        # validate against the allow-list. The SOAP template at
        # soap_templates.py:LDAP_PUT_FSTRING already injects the 'xsd:' prefix
        # into xsi:type, so a prefixed input would otherwise produce
        # xsi:type="xsd:xsd:string" and the server rejects the write with
        # AttributeTypeNotValidForEntry.
        if isinstance(data_type, str) and data_type.startswith("xsd:"):
            logging.warning("data_type with 'xsd:' prefix is deprecated, strip it")
            data_type = data_type[len("xsd:"):]
        if data_type not in self._PUT_ALLOWED_DATA_TYPES:
            raise ValueError(
                f"Unsupported data_type: {data_type!r} "
                f"(expected one of: {sorted(self._PUT_ALLOWED_DATA_TYPES)})"
            )

        put_vars = {
            "object_ref": object_ref, "uuid": str(uuid4()), "fqdn": self._fqdn,
            "operation": operation, "attribute": attribute,
            "data_type": data_type, "value": value,
        }
        put_msg = LDAP_PUT_FSTRING.format(**put_vars)
        self._nmf.send(put_msg)
        resp_str = self._nmf.recv()
        et = self._handle_str_to_xml(resp_str)
        if not et:
            logging.error(f"Failed to parse response for PUT operation on {object_ref}")
            return False

        body_s = et.find(f".//{{{NAMESPACES['s']}}}Body")
        body_soapenv = et.find(f".//{{{NAMESPACES['soapenv']}}}Body")
        body = body_s if body_s is not None else body_soapenv

        is_empty_body = (body is None or len(body) == 0 and (body.text is None or body.text.strip() == ""))
        has_put_response = body.find(f".//{{{NAMESPACES['wxf']}}}PutResponse") is not None if body is not None else False

        return is_empty_body or has_put_response

    def pull(
        self, query: str, attributes: list,
        print_incrementally: bool = False,
        base_object_dn_for_soap: str | None = None, use_schema=False,
        follow_referrals: bool = True
    ) -> ElementTree.Element | None:
        if self._resource != "Enumeration":
            raise NotImplementedError("Pull is only supported on 'pull' (Enumeration) clients")
        
        logging.debug(f"Starting pull: query='{query}', base_dn='{base_object_dn_for_soap}', attributes={len(attributes)}")

        def _do_query_enumeration():
            if use_schema:
                return self._query_enumeration(
                    remoteName=self._fqdn, nmf=self._nmf, query=query,
                    attributes=attributes, base_object_dn_for_soap=base_object_dn_for_soap, use_schema=True
                )
            return self._query_enumeration(
                remoteName=self._fqdn, nmf=self._nmf, query=query,
                attributes=attributes, base_object_dn_for_soap=base_object_dn_for_soap
            )

        try:
            try:
                enum_ctx = _do_query_enumeration()
            except (ConnectionError, OSError) as conn_err:
                # The long-lived ADWS/NMF session can be dropped by the DC
                # (idle timeout, load balancer, etc.) between pulls. Reconnect
                # once and retry the same query before giving up.
                logging.warning(
                    f"ADWS connection to {self._fqdn} was closed ({conn_err}). "
                    "Reconnecting and retrying the query once..."
                )
                try:
                    self._nmf = self._connect(self._fqdn, self._resource)
                    enum_ctx = _do_query_enumeration()
                except (ConnectionError, OSError) as retry_err:
                    logging.error(f"ADWS query to {self._fqdn} still failing after reconnect: {retry_err}")
                    return None
                except Exception as reconnect_error:
                    logging.error(f"Failed to reconnect to {self._fqdn}: {reconnect_error}")
                    return None
        except ADWSReferralError as e:
            if not follow_referrals:
                logging.warning(f"Referral detected but follow_referrals=False. Skipping.")
                return None
            
            logging.info(f"Following referral to: {e.referral_dc}")
            
            # Create a new connection to the referred DC
            try:
                referred_client = ADWSConnect(
                    fqdn=e.referral_dc,
                    domain=self._domain,
                    username=self._username,
                    auth=self._auth,
                    resource=self._resource
                )
                
                logging.info(f"Successfully connected to referred DC: {e.referral_dc}")
                
                # Retry the pull on the referred DC (without following further referrals)
                return referred_client.pull(
                    query=query,
                    attributes=attributes,
                    print_incrementally=print_incrementally,
                    base_object_dn_for_soap=base_object_dn_for_soap,
                    use_schema=use_schema,
                    follow_referrals=False  # Prevent infinite loops
                )
            except Exception as ref_error:
                logging.error(f"Failed to connect to referred DC {e.referral_dc}: {ref_error}")
                logging.warning("Falling back to original DC with empty results")
                return None
        
        if enum_ctx is None:
            logging.error("Failed to get enumeration context")
            return None
    
        
        logging.debug(f"Enumeration context obtained: {enum_ctx[:50]}...")
        
        ElementTree.register_namespace("wsen", NAMESPACES["wsen"])
        aggregated_items_root = ElementTree.Element(f"{{{NAMESPACES['wsen']}}}Items")
        
        more_results_expected = True
        batches_processed = 0
        total_items_in_all_batches = 0
        consecutive_failures = 0
        max_consecutive_failures = 3

        while more_results_expected:
            batches_processed += 1
            logging.debug(f"Pulling batch {batches_processed}...")

            try:
                batch_xml_response_et, batch_more_results = self._pull_results(
                    remoteName=self._fqdn, nmf=self._nmf, enum_ctx=enum_ctx
                )
            except (ConnectionError, OSError) as conn_err:
                # The enumeration context lives server-side and is tied to
                # this connection, so a dropped socket here can't be resumed
                # by reconnecting. Stop paginating and return what we have.
                logging.error(
                    f"ADWS connection to {self._fqdn} was closed while pulling batch "
                    f"{batches_processed} ({conn_err}). Returning {total_items_in_all_batches} "
                    "item(s) collected so far."
                )
                break

            if batch_xml_response_et is None:
                consecutive_failures += 1
                logging.error(f"Batch {batches_processed} failed (consecutive failures: {consecutive_failures})")
                
                if consecutive_failures >= max_consecutive_failures:
                    logging.error(f"Aborting pull after {consecutive_failures} consecutive failures")
                    break
                continue
            
            # Batch succeeded - now trust the server signal about pagination
            more_results_expected = batch_more_results

            # Reset counter on success
            consecutive_failures = 0

            items_in_batch_container = batch_xml_response_et.find(".//wsen:Items", NAMESPACES)

            current_batch_item_count = 0
            if items_in_batch_container is not None:
                for actual_ad_object_element in list(items_in_batch_container):
                    aggregated_items_root.append(actual_ad_object_element)
                    current_batch_item_count += 1
                total_items_in_all_batches += current_batch_item_count

            logging.debug(f"Batch {batches_processed}: {current_batch_item_count} items retrieved. More: {more_results_expected}")

            if print_incrementally and current_batch_item_count > 0 and items_in_batch_container is not None:
                temp_root_for_print = ElementTree.Element("RootForPrint")
                temp_items_for_print = ElementTree.SubElement(temp_root_for_print, f"{{{NAMESPACES['wsen']}}}Items")
                for el in items_in_batch_container:
                    temp_items_for_print.append(el)
                self._pretty_print_response(temp_root_for_print)

        if total_items_in_all_batches == 0:
            logging.warning(f"Query '{query}' returned 0 objects")
        else:
            #logging.info(f"Pull completed: {batches_processed} batches, {total_items_in_all_batches} total items")
            pass
        return aggregated_items_root

    @classmethod
    def pull_client(cls, ip: str, domain: str, username: str, auth: ADWSAuthType) -> Self:
        return cls(ip, domain, username, auth, "Enumeration")

    @classmethod
    def put_client(cls, ip: str, domain: str, username: str, auth: ADWSAuthType) -> Self:
        return cls(ip, domain, username, auth, "Resource")

    @classmethod
    def create_client(cls, ip: str, domain: str, username: str, auth: ADWSAuthType) -> Self:
        raise NotImplementedError()

    @classmethod
    def accounts_cap_client(cls, ip: str, domain: str, username: str, auth: ADWSAuthType) -> Self:
        raise NotImplementedError()

    @classmethod
    def topology_cap_client(cls, ip: str, domain: str, username: str, auth: ADWSAuthType) -> Self:
        """Open an MS-ADCAP TopologyManagement capability session on the DC.

        The ADWS endpoint path is ``Windows/TopologyManagement`` (MS-ADCAP
        section 3.2.3), served over the same net.tcp:9389 / MC-NMF framing /
        MS-NNS NegotiateStream carrier as the Enumeration and Resource
        endpoints. Use the resulting client's ``get_ad_forest`` and
        ``change_optional_feature`` methods.
        """
        return cls(ip, domain, username, auth, "TopologyManagement")

    @classmethod
    def account_cap_client(cls, ip: str, domain: str, username: str, auth: ADWSAuthType) -> Self:
        """Open an MS-ADCAP AccountManagement capability session on the DC.

        The ADWS endpoint path is ``Windows/AccountManagement`` (MS-ADCAP
        section 3.3), hosting operations such as ``TranslateName``,
        ``ChangePassword`` and group membership queries. Different endpoint
        from TopologyManagement -- the server rejects messages with a
        ContractFilter mismatch if the two are mixed.
        """
        return cls(ip, domain, username, auth, "AccountManagement")

    # ------------------------------------------------------------------
    # MS-ADCAP TopologyManagement primitives
    # ------------------------------------------------------------------
    # These three methods are the Linux-side counterparts to RSAT PowerShell
    # ``Get-ADForest``, ``TranslateName`` (NTDSAPI/MS-ADCAP) and
    # ``Enable-ADOptionalFeature``. Each method targets the server-side
    # consolidation primitives that MS-ADCAP exposes, which is why they are
    # interesting from a defensive-measurement angle: on SACL-tagged objects
    # they are expected to behave differently from the LDAP read/write path
    # observed via Event 4662. Measurement is handled in a separate prompt;
    # here we only ship the client-side implementation.

    def _tm_fault_or_tree(self, soap_payload: str):
        """Send a TopologyManagement SOAP payload, parse the reply, and return
        either the parsed ElementTree or an error dict when the server replied
        with a SOAP Fault.

        _handle_str_to_xml raises ADWSError on <s:Fault>, so we convert that
        exception into a plain dict here. The MS-ADCAP primitives report
        AccessDenied via Fault (non-privileged yuji on ChangeOptionalFeature,
        for example) and callers want to switch on the error label rather than
        handle exceptions.
        """
        self._nmf.send(soap_payload)
        resp_str = self._nmf.recv()
        try:
            et = self._handle_str_to_xml(resp_str)
        except ADWSError as exc:
            msg = str(exc)
            label = "AccessDenied" if "AccessDenied" in msg else (msg.splitlines()[0] if msg else "Fault")
            return {"error": label, "detail": msg}
        if et is None:
            return {"error": "ParseFailure", "detail": "server reply could not be parsed as XML"}
        return et

    def _tm_require_endpoint(self) -> None:
        if self._resource != "TopologyManagement":
            raise NotImplementedError("TopologyManagement primitives require a 'TopologyManagement' client")

    def get_ad_forest(self) -> dict:
        """Call MS-ADCAP ``GetADForest`` for ``self._domain``.

        Returns:
            Flat dict with every child text() of the response body, or an
            ``{"error": "...", "detail": "..."}`` dict on SOAP Fault.
        """
        self._tm_require_endpoint()
        soap = TM_GET_AD_FOREST_FSTRING.format(uuid=str(uuid4()), fqdn=self._fqdn)
        result = self._tm_fault_or_tree(soap)
        if isinstance(result, dict):
            return result
        ca_ns = NAMESPACES["ca"]
        payload = result.find(f".//{{{ca_ns}}}GetADForestResponse")
        if payload is None:
            payload = result.find(f".//{{{ca_ns}}}GetADForestResult")
        if payload is None:
            payload = result
        return _parse_ad_forest_payload(payload)

    def get_version(self) -> dict:
        """Call MS-ADCAP ``GetVersion``.

        Fingerprints the ADWS service version advertised by the DC (useful
        to distinguish Windows Server builds and as the cheapest end-to-end
        health check of the TopologyManagement endpoint).

        Returns:
            A dict with ``VersionMajor`` (str), ``VersionMinor`` (str),
            ``VersionString`` (str), or ``{"error": ..., "detail": ...}``
            on SOAP Fault.
        """
        self._tm_require_endpoint()
        soap = TM_GET_VERSION_FSTRING.format(uuid=str(uuid4()), fqdn=self._fqdn)
        result = self._tm_fault_or_tree(soap)
        if isinstance(result, dict):
            return result
        ca_ns = NAMESPACES["ca"]
        out: dict = {}
        for tag in ("VersionMajor", "VersionMinor", "VersionString"):
            elem = result.find(f".//{{{ca_ns}}}{tag}")
            if elem is None:
                # Fallback: match by local name regardless of namespace prefix.
                for leaf in result.iter():
                    if _localname_from_tag(leaf.tag) == tag:
                        elem = leaf
                        break
            out[tag] = (elem.text or "").strip() if elem is not None and elem.text else ""
        return out

    def get_ad_domain(self, identity: str | None = None) -> dict:
        """Call MS-ADCAP ``GetADDomain``.

        Returns the domain object hosted by the contacted DC, or the domain
        identified by ``identity`` when supplied (DN / NetBIOS / DNS name).
        Response shape mirrors ``GetADForest`` with a ``<Domain>`` wrapper.

        Returns:
            A dict with the parsed Domain fields (array fields default to
            ``[]`` when empty, nullable scalars to ``None``), or
            ``{"error": ..., "detail": ...}`` on SOAP Fault. ``DomainSID``
            is decoded to canonical ``S-1-5-…`` form.
        """
        self._tm_require_endpoint()
        identity_block = f"<ca:Identity>{identity}</ca:Identity>" if identity else ""
        soap = TM_GET_AD_DOMAIN_FSTRING.format(
            uuid=str(uuid4()), fqdn=self._fqdn, identity_block=identity_block,
        )
        result = self._tm_fault_or_tree(soap)
        if isinstance(result, dict):
            return result
        ca_ns = NAMESPACES["ca"]
        payload = result.find(f".//{{{ca_ns}}}GetADDomainResponse")
        if payload is None:
            payload = result.find(f".//{{{ca_ns}}}GetADDomainResult")
        if payload is None:
            payload = result
        parsed = _parse_ad_domain_payload(payload)
        if parsed.get("DomainSID"):
            parsed["DomainSID"] = _decode_binary_sid_b64(parsed["DomainSID"])
        return parsed

    def get_ad_domain_controller(self, ntds_settings_dn: list) -> dict:
        """Call MS-ADCAP ``GetADDomainController``.

        The server rejects empty requests with an ArgumentError on the
        ``NtdsSettingsDN`` parameter even though the WSDL marks it optional
        (observed empirically). Caller MUST supply at least one DN of the
        form ``CN=NTDS Settings,CN=<DC>,CN=Servers,CN=<Site>,CN=Sites,
        CN=Configuration,<rootDN>``. Discoverable via LDAP or by inspecting
        ``ReplicaDirectoryServer`` from a prior ``get_ad_forest`` /
        ``get_ad_domain``.

        Args:
            ntds_settings_dn: non-empty list of NTDS Settings DNs.

        Returns:
            A dict with the parsed DomainController fields, or
            ``{"error": ..., "detail": ...}`` on SOAP Fault.
        """
        self._tm_require_endpoint()
        if not ntds_settings_dn:
            raise ValueError(
                "ntds_settings_dn must be a non-empty list of DN strings "
                "(the server rejects an empty NtdsSettingsDN with an "
                "ArgumentError even though the WSDL marks it optional)"
            )
        ntds_string_items = "".join(
            f"<b:string>{dn}</b:string>" for dn in ntds_settings_dn
        )
        soap = TM_GET_AD_DOMAIN_CONTROLLER_FSTRING.format(
            uuid=str(uuid4()), fqdn=self._fqdn, ntds_string_items=ntds_string_items,
        )
        result = self._tm_fault_or_tree(soap)
        if isinstance(result, dict):
            return result
        ca_ns = NAMESPACES["ca"]
        payload = result.find(f".//{{{ca_ns}}}GetADDomainControllerResponse")
        if payload is None:
            payload = result.find(f".//{{{ca_ns}}}GetADDomainControllerResult")
        if payload is None:
            payload = result
        return _parse_dc_payload(payload)

    def translate_name(self, name: str, format_offered: int = 1, format_desired: int = 2) -> dict:
        """Call MS-ADCAP ``TranslateName``.

        Routed through the AccountManagement capability endpoint
        (``Windows/AccountManagement``, MS-ADCAP section 3.3.4.6), not
        TopologyManagement -- the server rejects a message sent to the
        wrong endpoint with a ContractFilter mismatch.

        MS-ADCAP's ``ActiveDirectoryNameFormat`` only defines
        ``DistinguishedName`` (1) and ``CanonicalName`` (2) -- the richer
        EXTENDED_NAME_FORMAT values (SAM / Display / UPN / SPN / UniqueId)
        from Win32 LSA are unavailable through this contract. In practice
        the implementation appears to be unidirectional (DN -> Canonical);
        the reverse combo (offered=Canonical, desired=DN) triggers a
        ``FormatDesired is not supported`` ArgumentError. Defaults reflect
        the supported direction: input is a DN, output is the canonical
        path.

        Args:
            name: input principal to translate (default: DN).
            format_offered: input format code. 1 = DistinguishedName
                (default), 2 = CanonicalName.
            format_desired: desired output format. 2 = CanonicalName
                (default), 1 = DistinguishedName.
        """
        if self._resource != "AccountManagement":
            raise NotImplementedError("translate_name requires an 'AccountManagement' client (use ADWSConnect.account_cap_client)")
        soap = TM_TRANSLATE_NAME_FSTRING.format(
            uuid=str(uuid4()), fqdn=self._fqdn,
            name=name,
            format_offered=_ad_name_format_name(format_offered),
            format_desired=_ad_name_format_name(format_desired),
        )
        result = self._tm_fault_or_tree(soap)
        if isinstance(result, dict):
            return result
        # Response strings may live in the Serialization/Arrays namespace, in
        # the CustomActions namespace, or come back unqualified -- accept any
        # local-name == "string" leaf under the body.
        translated = [elem.text for elem in result.iter() if elem.text and (
            elem.tag.split("}", 1)[-1] if "}" in elem.tag else elem.tag) == "string"]
        return {"input": name, "format_offered": format_offered, "format_desired": format_desired, "translated": translated}

    def change_optional_feature(self, distinguished_name: str, feature_guid: str, enable: bool = True) -> dict:
        """Call MS-ADCAP ``ChangeOptionalFeature``.

        Args:
            distinguished_name: DN of the context where the feature is
                toggled. For forest-level features (e.g. Recycle Bin) this
                is typically ``CN=Partitions,CN=Configuration,<rootDN>``.
            feature_guid: GUID of the optional feature.
            enable: True to enable, False to disable.
        """
        self._tm_require_endpoint()
        soap = TM_CHANGE_OPTIONAL_FEATURE_FSTRING.format(
            uuid=str(uuid4()), fqdn=self._fqdn,
            distinguished_name=distinguished_name,
            feature_guid=feature_guid, enable_bool=str(bool(enable)).lower(),
        )
        result = self._tm_fault_or_tree(soap)
        if isinstance(result, dict):
            return result
        # No specific payload fields on success -- the write is confirmed by
        # the absence of a Fault and a 2xx-equivalent empty Body.
        return {"distinguished_name": distinguished_name, "feature_guid": feature_guid, "enable": bool(enable), "result": "ok"}
