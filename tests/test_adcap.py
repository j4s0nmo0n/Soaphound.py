"""Unit tests for the MS-ADCAP CustomActions primitives.

These tests exercise ADWSConnect.get_ad_forest, translate_name and
change_optional_feature. No actual ADWS connection is opened: an ADWSConnect
instance is built via object.__new__ and _nmf is replaced by a MagicMock, so
.send() captures the SOAP payload for inspection and .recv() returns a fake
server reply.

The three operations split over two endpoints:
    * TopologyManagement -> get_ad_forest, change_optional_feature
    * AccountManagement  -> translate_name
"""
import unittest
from unittest.mock import MagicMock

from soaphound.ad.adws import (
    ADWSConnect, _ad_name_format_name,
    _parse_ad_principal, _parse_principal_list,
    partition_dn_from_identity,
)
from soaphound.ad.soap_templates import NAMESPACES
from soaphound.soaphound import _format_principal_list_powershell


_CA_NS = NAMESPACES["ca"]
_SERA_NS = "http://schemas.microsoft.com/2003/10/Serialization/Arrays"


def _build_cap_client(resource: str) -> ADWSConnect:
    """Return an ADWSConnect instance wired as a <resource> capability client,
    with _nmf replaced by a MagicMock. No real socket is opened."""
    client = object.__new__(ADWSConnect)
    client._fqdn = "dc.example.local"
    client._domain = "example.local"
    client._username = "svc"
    client._auth = None
    client._resource = resource
    client._nmf = MagicMock()
    return client


def _wrap_envelope(body_xml: str) -> str:
    """Build a minimal SOAP 1.2 reply envelope around a ca:* body fragment."""
    return (
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        f'xmlns:ca="{_CA_NS}" '
        f'xmlns:sera="{_SERA_NS}">'
        '<s:Header/>'
        f'<s:Body>{body_xml}</s:Body>'
        '</s:Envelope>'
    )


def _fault_envelope(reason: str = "AccessDenied", detail: str = "yuji is not a Domain Admin") -> str:
    return (
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        '<s:Header/>'
        '<s:Body>'
        '<s:Fault>'
        f'<s:Code><s:Value>s:Receiver</s:Value></s:Code>'
        f'<s:Reason><s:Text xml:lang="en">{reason}</s:Text></s:Reason>'
        f'<s:Detail>{detail}</s:Detail>'
        '</s:Fault>'
        '</s:Body>'
        '</s:Envelope>'
    )


class AdcapDispatchTests(unittest.TestCase):
    def test_get_ad_forest_sends_right_template_and_parses_reply(self):
        client = _build_cap_client("TopologyManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetADForestResponse>'
            '<ca:GetADForestResult>'
            '<ca:Name>example.local</ca:Name>'
            '<ca:ForestMode>Windows2016Forest</ca:ForestMode>'
            '<ca:RootDomain>example.local</ca:RootDomain>'
            '</ca:GetADForestResult>'
            '</ca:GetADForestResponse>'
        )

        result = client.get_ad_forest()

        sent = client._nmf.send.call_args[0][0]
        self.assertIn("CustomActions/TopologyManagement/GetADForest</a:Action>", sent)
        self.assertIn("<ca:Server>ldap:389</ca:Server>", sent)
        self.assertIn("<ca:GetADForestRequest/>", sent)
        self.assertIn('net.tcp://dc.example.local:9389/ActiveDirectoryWebServices/Windows/TopologyManagement', sent)

        self.assertEqual(result.get("Name"), "example.local")
        self.assertEqual(result.get("ForestMode"), "Windows2016Forest")
        self.assertEqual(result.get("RootDomain"), "example.local")

    def test_get_ad_forest_collects_arrayof_string_wrappers(self):
        """Multi-valued fields (Sites, Domains, ApplicationPartitions, ...)
        wrap their values in Microsoft's ArrayOf* with ``<a:string>`` children.
        Each wrapper must land as a list under its parent name — the old flat
        iter() implementation overwrote them with a single ``"string": "..."``
        key and lost the parent name entirely."""
        client = _build_cap_client("TopologyManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetADForestResponse>'
            '<ca:GetADForestResult>'
            '<ca:Name>example.local</ca:Name>'
            '<ca:RootDomain>example.local</ca:RootDomain>'
            '<ca:ForestMode>10</ca:ForestMode>'
            '<ca:SchemaMaster>DC-01.example.local</ca:SchemaMaster>'
            '<ca:DomainNamingMaster>DC-01.example.local</ca:DomainNamingMaster>'
            '<ca:ApplicationPartitions>'
            '<sera:string>DC=DomainDnsZones,DC=example,DC=local</sera:string>'
            '<sera:string>DC=DomainDnsZones,DC=sub,DC=example,DC=local</sera:string>'
            '<sera:string>DC=ForestDnsZones,DC=example,DC=local</sera:string>'
            '</ca:ApplicationPartitions>'
            '<ca:Domains>'
            '<sera:string>example.local</sera:string>'
            '<sera:string>sub.example.local</sera:string>'
            '</ca:Domains>'
            '<ca:GlobalCatalogs>'
            '<sera:string>DC-01.example.local</sera:string>'
            '<sera:string>DC-02.sub.example.local</sera:string>'
            '</ca:GlobalCatalogs>'
            '<ca:Sites>'
            '<sera:string>Default-First-Site-Name</sera:string>'
            '</ca:Sites>'
            '<ca:UpnSuffixes/>'
            '<ca:SpnSuffixes/>'
            '<ca:CrossForestReferences/>'
            '</ca:GetADForestResult>'
            '</ca:GetADForestResponse>'
        )

        result = client.get_ad_forest()

        # Scalars survive.
        self.assertEqual(result["Name"], "example.local")
        self.assertEqual(result["RootDomain"], "example.local")
        self.assertEqual(result["ForestMode"], "10")
        self.assertEqual(result["SchemaMaster"], "DC-01.example.local")
        self.assertEqual(result["DomainNamingMaster"], "DC-01.example.local")

        # Multi-valued wrappers land as lists under the parent name,
        # NOT under "string".
        self.assertNotIn("string", result)
        self.assertEqual(
            result["ApplicationPartitions"],
            [
                "DC=DomainDnsZones,DC=example,DC=local",
                "DC=DomainDnsZones,DC=sub,DC=example,DC=local",
                "DC=ForestDnsZones,DC=example,DC=local",
            ],
        )
        self.assertEqual(result["Domains"], ["example.local", "sub.example.local"])
        self.assertEqual(result["GlobalCatalogs"], ["DC-01.example.local", "DC-02.sub.example.local"])
        self.assertEqual(result["Sites"], ["Default-First-Site-Name"])

        # Empty wrappers normalize to [] so JSON consumers can loop without
        # a per-field null check.
        self.assertEqual(result["UpnSuffixes"], [])
        self.assertEqual(result["SpnSuffixes"], [])
        self.assertEqual(result["CrossForestReferences"], [])

    def test_get_ad_forest_normalizes_nil_array_to_empty_list(self):
        """A known array field with i:nil="true" collapses to [], not None."""
        client = _build_cap_client("TopologyManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetADForestResponse>'
            '<ca:GetADForestResult>'
            '<ca:Name>example.local</ca:Name>'
            '<ca:Sites xmlns:i="http://www.w3.org/2001/XMLSchema-instance" i:nil="true"/>'
            '</ca:GetADForestResult>'
            '</ca:GetADForestResponse>'
        )
        result = client.get_ad_forest()
        self.assertEqual(result["Sites"], [])
        self.assertEqual(result["Name"], "example.local")

    def test_translate_name_sends_right_template_and_parses_reply(self):
        client = _build_cap_client("AccountManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:TranslateNameResponse>'
            '<ca:TranslateNameResult>'
            '<sera:string>CN=svc,OU=Users,DC=example,DC=local</sera:string>'
            '</ca:TranslateNameResult>'
            '</ca:TranslateNameResponse>'
        )

        # MS-ADCAP TranslateName is unidirectional DN -> Canonical. Pass
        # the DN as input and let the method defaults pick the output
        # format (CanonicalName). Explicit args kept for readability.
        result = client.translate_name(
            "CN=svc,OU=Users,DC=example,DC=local",
            format_offered=1, format_desired=2,
        )

        sent = client._nmf.send.call_args[0][0]
        self.assertIn("CustomActions/AccountManagement/TranslateName</a:Action>", sent)
        self.assertIn("<ca:Server>ldap:389</ca:Server>", sent)
        self.assertIn("<ca:TranslateNameRequest>", sent)
        self.assertIn("<sera:string>CN=svc,OU=Users,DC=example,DC=local</sera:string>", sent)
        # WCF DataContract serialization: enum members as names, not ints.
        # The MS-ADCAP contract only defines DistinguishedName (1) and
        # CanonicalName (2) -- see _AD_NAME_FORMAT_NAMES in adws.py.
        self.assertIn("<ca:FormatOffered>DistinguishedName</ca:FormatOffered>", sent)
        self.assertIn("<ca:FormatDesired>CanonicalName</ca:FormatDesired>", sent)
        self.assertNotIn("<ca:FormatOffered>1</ca:FormatOffered>", sent)
        self.assertNotIn("<ca:FormatDesired>2</ca:FormatDesired>", sent)
        self.assertIn('net.tcp://dc.example.local:9389/ActiveDirectoryWebServices/Windows/AccountManagement', sent)

        self.assertEqual(result["input"], "CN=svc,OU=Users,DC=example,DC=local")
        self.assertEqual(result["format_offered"], 1)
        self.assertEqual(result["format_desired"], 2)
        self.assertEqual(result["translated"], ["CN=svc,OU=Users,DC=example,DC=local"])

    def test_change_optional_feature_sends_right_template_and_parses_reply(self):
        client = _build_cap_client("TopologyManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:ChangeOptionalFeatureResponse/>'
        )

        guid = "766ddcd8-acd0-445e-f3b9-a7f9b6744f2a"  # Recycle Bin
        dn = "CN=Partitions,CN=Configuration,DC=example,DC=local"
        result = client.change_optional_feature(dn, guid, enable=True)

        sent = client._nmf.send.call_args[0][0]
        self.assertIn("CustomActions/TopologyManagement/ChangeOptionalFeature</a:Action>", sent)
        self.assertIn("<ca:Server>ldap:389</ca:Server>", sent)
        self.assertIn("<ca:ChangeOptionalFeatureRequest>", sent)
        self.assertIn(f"<ca:DistinguishedName>{dn}</ca:DistinguishedName>", sent)
        self.assertIn(f"<ca:FeatureId>{guid}</ca:FeatureId>", sent)
        self.assertIn("<ca:Enable>true</ca:Enable>", sent)

        self.assertEqual(
            result,
            {"distinguished_name": dn, "feature_guid": guid, "enable": True, "result": "ok"},
        )

    def test_fault_returned_as_error_dict_not_raised(self):
        """A SOAP Fault (e.g. AccessDenied) is reported as a plain error dict
        so callers can switch on it instead of handling exceptions."""
        client = _build_cap_client("TopologyManagement")
        client._nmf.recv.return_value = _fault_envelope(reason="AccessDenied", detail="yuji is non-privileged")

        result = client.change_optional_feature(
            "CN=Partitions,CN=Configuration,DC=example,DC=local",
            "00000000-0000-0000-0000-000000000000",
            enable=True,
        )

        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("error"), "AccessDenied")
        self.assertIn("yuji is non-privileged", result.get("detail", ""))

    def test_methods_refuse_wrong_endpoint(self):
        """Each primitive refuses to run against the wrong capability endpoint.

        * get_ad_forest and change_optional_feature require TopologyManagement.
        * translate_name requires AccountManagement.
        """
        # Enumeration client refuses all three.
        client = _build_cap_client("Enumeration")
        with self.assertRaises(NotImplementedError):
            client.get_ad_forest()
        with self.assertRaises(NotImplementedError):
            client.translate_name("foo")
        with self.assertRaises(NotImplementedError):
            client.change_optional_feature(
                "CN=Partitions,CN=Configuration,DC=example,DC=local",
                "00000000-0000-0000-0000-000000000000",
            )
        client._nmf.send.assert_not_called()

        # TopologyManagement client refuses translate_name (AM-only).
        tm = _build_cap_client("TopologyManagement")
        with self.assertRaises(NotImplementedError):
            tm.translate_name("foo")
        tm._nmf.send.assert_not_called()

        # AccountManagement client refuses the two Topology primitives.
        am = _build_cap_client("AccountManagement")
        with self.assertRaises(NotImplementedError):
            am.get_ad_forest()
        with self.assertRaises(NotImplementedError):
            am.change_optional_feature(
                "CN=Partitions,CN=Configuration,DC=example,DC=local",
                "00000000-0000-0000-0000-000000000000",
            )
        am._nmf.send.assert_not_called()


class AdNameFormatNameTests(unittest.TestCase):
    """_ad_name_format_name converts MS-ADCAP ActiveDirectoryNameFormat
    integer values (1=DistinguishedName, 2=CanonicalName) to the enum member
    names required by the AccountManagement endpoint. The MS-ADCAP contract
    does NOT support the richer EXTENDED_NAME_FORMAT values (SAM, Display,
    UPN, SPN, UniqueId, Canonical-Ex, DnsDomain). Strings pass through."""

    def test_known_integer_values_map_to_member_names(self):
        cases = [
            (1, "DistinguishedName"),
            (2, "CanonicalName"),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(_ad_name_format_name(value), expected)

    def test_string_passes_through_unchanged(self):
        self.assertEqual(_ad_name_format_name("CanonicalName"), "CanonicalName")

    def test_unsupported_extended_name_format_values_raise(self):
        """EXTENDED_NAME_FORMAT values (secext.h) not part of MS-ADCAP must
        raise -- they would be silently accepted and then rejected by the
        server with a WCF deserializer fault."""
        for bad in (0, 3, 6, 7, 8, 9, 10, 12):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                _ad_name_format_name(bad)

    def test_unknown_integer_raises_value_error(self):
        for bad in (4, 5, 11, 13, 14, 99, -1):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                _ad_name_format_name(bad)


class GetVersionTests(unittest.TestCase):
    """ADWSConnect.get_version — scalar-only reply, single-line output."""

    def test_sends_right_template_and_parses_three_scalars(self):
        client = _build_cap_client("TopologyManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetVersionResponse>'
            '<ca:VersionMajor>1</ca:VersionMajor>'
            '<ca:VersionMinor>1</ca:VersionMinor>'
            '<ca:VersionString>Active Directory Web Services v1.1</ca:VersionString>'
            '</ca:GetVersionResponse>'
        )
        result = client.get_version()
        sent = client._nmf.send.call_args[0][0]
        self.assertIn("CustomActions/TopologyManagement/GetVersion</a:Action>", sent)
        self.assertIn("<ca:GetVersionRequest/>", sent)
        self.assertEqual(result, {
            "VersionMajor": "1",
            "VersionMinor": "1",
            "VersionString": "Active Directory Web Services v1.1",
        })

    def test_tolerates_missing_fields(self):
        client = _build_cap_client("TopologyManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetVersionResponse/>'
        )
        result = client.get_version()
        self.assertEqual(result, {
            "VersionMajor": "",
            "VersionMinor": "",
            "VersionString": "",
        })


class GetADDomainTests(unittest.TestCase):
    """ADWSConnect.get_ad_domain — <Domain> wrapper, same shape as forest.
    Also exercises DomainSID base64 → canonical SID decoding."""

    def test_sends_right_template_and_parses_domain_wrapper(self):
        client = _build_cap_client("TopologyManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetADDomainResponse xmlns:i="http://www.w3.org/2001/XMLSchema-instance">'
            '<ca:Domain>'
            '<ca:AllowedDNSSuffixes i:nil="true"/>'
            '<ca:AppliedGroupPolicies>'
            '<sera:string>CN=Default Domain Policy,CN=Policies,CN=System,DC=example,DC=local</sera:string>'
            '</ca:AppliedGroupPolicies>'
            '<ca:ChildDomains>'
            '<sera:string>sub.example.local</sera:string>'
            '</ca:ChildDomains>'
            '<ca:DNSRoot>example.local</ca:DNSRoot>'
            '<ca:DistinguishedName>DC=example,DC=local</ca:DistinguishedName>'
            '<ca:DomainMode>7</ca:DomainMode>'
            # Base64 of a canonical SID — decoded by _decode_binary_sid_b64
            '<ca:DomainSID>AQQAAAAAAAUVAAAAMvS+ZFce3OVQRHoW</ca:DomainSID>'
            '<ca:Forest>example.local</ca:Forest>'
            '<ca:InfrastructureMaster>DC-01.example.local</ca:InfrastructureMaster>'
            '<ca:ManagedBy i:nil="true"/>'
            '<ca:Name>example</ca:Name>'
            '<ca:NetBIOSName>EXAMPLE</ca:NetBIOSName>'
            '<ca:ObjectTypes>'
            '<sera:string>domainDNS</sera:string>'
            '</ca:ObjectTypes>'
            '<ca:ParentDomain i:nil="true"/>'
            '<ca:PDCEmulator>DC-01.example.local</ca:PDCEmulator>'
            '<ca:RIDMaster>DC-01.example.local</ca:RIDMaster>'
            '<ca:ReadOnlyReplicaDirectoryServer i:nil="true"/>'
            '<ca:ReplicaDirectoryServer>'
            '<sera:string>DC-01.example.local</sera:string>'
            '<sera:string>DC-02.example.local</sera:string>'
            '</ca:ReplicaDirectoryServer>'
            '<ca:SubordinateReferences>'
            '<sera:string>DC=ForestDnsZones,DC=example,DC=local</sera:string>'
            '</ca:SubordinateReferences>'
            '</ca:Domain>'
            '</ca:GetADDomainResponse>'
        )
        result = client.get_ad_domain()
        sent = client._nmf.send.call_args[0][0]
        self.assertIn("CustomActions/TopologyManagement/GetADDomain</a:Action>", sent)
        # Scalars survive
        self.assertEqual(result["Name"], "example")
        self.assertEqual(result["DNSRoot"], "example.local")
        self.assertEqual(result["NetBIOSName"], "EXAMPLE")
        self.assertEqual(result["PDCEmulator"], "DC-01.example.local")
        # Arrays
        self.assertEqual(result["ChildDomains"], ["sub.example.local"])
        self.assertEqual(result["ReplicaDirectoryServer"],
                         ["DC-01.example.local", "DC-02.example.local"])
        self.assertEqual(result["ObjectTypes"], ["domainDNS"])
        # Nil arrays normalise to []
        self.assertEqual(result["AllowedDNSSuffixes"], [])
        self.assertEqual(result["ReadOnlyReplicaDirectoryServer"], [])
        # Nil scalars stay None
        self.assertIsNone(result["ManagedBy"])
        self.assertIsNone(result["ParentDomain"])
        # Base64 DomainSID decoded to canonical form
        self.assertTrue(result["DomainSID"].startswith("S-1-5-21-"))

    def test_identity_added_to_body_when_supplied(self):
        client = _build_cap_client("TopologyManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetADDomainResponse>'
            '<ca:Domain><ca:Name>example</ca:Name></ca:Domain>'
            '</ca:GetADDomainResponse>'
        )
        client.get_ad_domain(identity="example.local")
        sent = client._nmf.send.call_args[0][0]
        self.assertIn("<ca:Identity>example.local</ca:Identity>", sent)

    def test_identity_omitted_by_default(self):
        client = _build_cap_client("TopologyManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetADDomainResponse>'
            '<ca:Domain><ca:Name>example</ca:Name></ca:Domain>'
            '</ca:GetADDomainResponse>'
        )
        client.get_ad_domain()
        sent = client._nmf.send.call_args[0][0]
        self.assertNotIn("<ca:Identity>", sent)


class GetADDomainControllerTests(unittest.TestCase):
    """ADWSConnect.get_ad_domain_controller — mandatory NtdsSettingsDN
    (empirical server-side requirement), DomainControllers plural wrapper
    containing <ActiveDirectoryDomainController>, OperationMasterRole
    nested array flattening."""

    def test_empty_ntds_settings_dn_raises_before_any_network_call(self):
        client = _build_cap_client("TopologyManagement")
        with self.assertRaises(ValueError):
            client.get_ad_domain_controller([])
        client._nmf.send.assert_not_called()

    def test_body_wraps_each_dn_in_a_b_string_element(self):
        client = _build_cap_client("TopologyManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetADDomainControllerResponse>'
            '<ca:DomainControllers>'
            '<ca:ActiveDirectoryDomainController><ca:Name>DC-01</ca:Name></ca:ActiveDirectoryDomainController>'
            '</ca:DomainControllers>'
            '</ca:GetADDomainControllerResponse>'
        )
        dns = [
            "CN=NTDS Settings,CN=DC-01,CN=Servers,CN=Site1,CN=Sites,CN=Configuration,DC=example,DC=local",
            "CN=NTDS Settings,CN=DC-02,CN=Servers,CN=Site1,CN=Sites,CN=Configuration,DC=example,DC=local",
        ]
        client.get_ad_domain_controller(dns)
        sent = client._nmf.send.call_args[0][0]
        self.assertIn("CustomActions/TopologyManagement/GetADDomainController</a:Action>", sent)
        self.assertIn("<ca:NtdsSettingsDN", sent)
        for dn in dns:
            self.assertIn(f"<b:string>{dn}</b:string>", sent)

    def test_parses_scalars_arrays_and_operation_master_role_flatten(self):
        """``<OperationMasterRole>`` wraps repeated typed children (NOT
        <string>) — must flatten to list of role names.
        ``<Partitions>`` wraps repeated ``<string>`` — list of DNs."""
        client = _build_cap_client("TopologyManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetADDomainControllerResponse xmlns:i="http://www.w3.org/2001/XMLSchema-instance">'
            '<ca:DomainControllers>'
            '<ca:ActiveDirectoryDomainController>'
            '<ca:Name>DC-01</ca:Name>'
            '<ca:HostName>DC-01.example.local</ca:HostName>'
            '<ca:Enabled>true</ca:Enabled>'
            '<ca:IsGlobalCatalog>true</ca:IsGlobalCatalog>'
            '<ca:IsReadOnly>false</ca:IsReadOnly>'
            '<ca:LdapPort>389</ca:LdapPort>'
            '<ca:SslPort>636</ca:SslPort>'
            '<ca:OsHotFix i:nil="true"/>'
            '<ca:OperationMasterRole>'
            '<ca:ActiveDirectoryOperationMasterRole>SchemaMaster</ca:ActiveDirectoryOperationMasterRole>'
            '<ca:ActiveDirectoryOperationMasterRole>DomainNamingMaster</ca:ActiveDirectoryOperationMasterRole>'
            '<ca:ActiveDirectoryOperationMasterRole>PDCEmulator</ca:ActiveDirectoryOperationMasterRole>'
            '<ca:ActiveDirectoryOperationMasterRole>RIDMaster</ca:ActiveDirectoryOperationMasterRole>'
            '<ca:ActiveDirectoryOperationMasterRole>InfrastructureMaster</ca:ActiveDirectoryOperationMasterRole>'
            '</ca:OperationMasterRole>'
            '<ca:Partitions xmlns:b="http://schemas.microsoft.com/2003/10/Serialization/Arrays">'
            '<b:string>DC=example,DC=local</b:string>'
            '<b:string>CN=Configuration,DC=example,DC=local</b:string>'
            '</ca:Partitions>'
            '<ca:Site>Default-First-Site-Name</ca:Site>'
            '</ca:ActiveDirectoryDomainController>'
            '</ca:DomainControllers>'
            '</ca:GetADDomainControllerResponse>'
        )
        result = client.get_ad_domain_controller([
            "CN=NTDS Settings,CN=DC-01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=local",
        ])
        self.assertEqual(result["Name"], "DC-01")
        self.assertEqual(result["HostName"], "DC-01.example.local")
        self.assertEqual(result["Enabled"], "true")
        self.assertEqual(result["LdapPort"], "389")
        self.assertEqual(result["SslPort"], "636")
        self.assertEqual(result["Site"], "Default-First-Site-Name")
        self.assertIsNone(result["OsHotFix"])
        self.assertEqual(
            result["OperationMasterRole"],
            ["SchemaMaster", "DomainNamingMaster",
             "PDCEmulator", "RIDMaster", "InfrastructureMaster"],
        )
        self.assertEqual(
            result["Partitions"],
            ["DC=example,DC=local", "CN=Configuration,DC=example,DC=local"],
        )


class DecodeBinarySidTests(unittest.TestCase):
    """_decode_binary_sid_b64 — base64 binary SID → canonical dotted form."""

    def test_decodes_base64_binary_sid_to_canonical(self):
        from base64 import b64encode
        from impacket.ldap.ldaptypes import LDAP_SID
        from soaphound.ad.adws import _decode_binary_sid_b64
        sid = LDAP_SID()
        sid.fromCanonical("S-1-5-21-1687579186-3856638039-375210320")
        wire = b64encode(sid.getData()).decode()
        self.assertEqual(
            _decode_binary_sid_b64(wire),
            "S-1-5-21-1687579186-3856638039-375210320",
        )

    def test_passes_through_already_canonical_sid(self):
        from soaphound.ad.adws import _decode_binary_sid_b64
        self.assertEqual(
            _decode_binary_sid_b64("S-1-5-21-1-2-3"),
            "S-1-5-21-1-2-3",
        )

    def test_passes_through_empty_string(self):
        from soaphound.ad.adws import _decode_binary_sid_b64
        self.assertEqual(_decode_binary_sid_b64(""), "")


def _sid_b64(canonical: str) -> str:
    """Encode a canonical SID string the way the server ships it on the
    wire (xs:base64Binary of the raw LDAP_SID bytes)."""
    from base64 import b64encode
    from impacket.ldap.ldaptypes import LDAP_SID
    s = LDAP_SID()
    s.fromCanonical(canonical)
    return b64encode(s.getData()).decode()


class PartitionDnFromIdentityTests(unittest.TestCase):
    """Trailing DC= derivation used to auto-fill PartitionDN (which the
    server requires despite the WSDL marking it optional)."""

    def test_derives_from_user_dn(self):
        self.assertEqual(
            partition_dn_from_identity(
                "CN=alice,CN=Users,DC=example,DC=local"
            ),
            "DC=example,DC=local",
        )

    def test_derives_from_group_dn_with_space(self):
        self.assertEqual(
            partition_dn_from_identity(
                "CN=Domain Admins,CN=Users,DC=example,DC=local"
            ),
            "DC=example,DC=local",
        )

    def test_handles_three_level_dc(self):
        self.assertEqual(
            partition_dn_from_identity(
                "CN=foo,OU=sub,DC=sub,DC=example,DC=com"
            ),
            "DC=sub,DC=example,DC=com",
        )

    def test_returns_none_for_canonical_name(self):
        self.assertIsNone(
            partition_dn_from_identity("example.local/Users/alice")
        )

    def test_returns_none_for_empty_input(self):
        self.assertIsNone(partition_dn_from_identity(""))
        self.assertIsNone(partition_dn_from_identity(None))


class GetADGroupMemberTests(unittest.TestCase):
    """GetADGroupMember — AccountManagement endpoint required; identity
    field is <GroupDN>; body alphabetical FormatOffered < GroupDN <
    PartitionDN; parses <Members><ActiveDirectoryPrincipal> entries."""

    def test_requires_account_management_endpoint(self):
        tm = _build_cap_client("TopologyManagement")
        with self.assertRaises(NotImplementedError):
            tm.get_ad_group_member(
                "CN=g,CN=Users,DC=example,DC=local",
                partition_dn="DC=example,DC=local",
            )

    def test_rejects_empty_partition_dn_when_not_derivable(self):
        am = _build_cap_client("AccountManagement")
        with self.assertRaises(ValueError):
            am.get_ad_group_member("not-a-dn")

    def test_body_contains_group_dn_and_partition_dn_in_alphabetical_order(self):
        client = _build_cap_client("AccountManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetADGroupMemberResponse><ca:Members/></ca:GetADGroupMemberResponse>'
        )
        client.get_ad_group_member(
            "CN=Admins,CN=Users,DC=example,DC=local",
            partition_dn="DC=example,DC=local",
        )
        sent = client._nmf.send.call_args[0][0]
        self.assertIn(
            "AccountManagement/GetADGroupMember</a:Action>", sent,
        )
        self.assertIn("<ca:FormatOffered>DistinguishedName</ca:FormatOffered>", sent)
        self.assertIn(
            "<ca:GroupDN>CN=Admins,CN=Users,DC=example,DC=local</ca:GroupDN>", sent,
        )
        self.assertIn("<ca:PartitionDN>DC=example,DC=local</ca:PartitionDN>", sent)
        self.assertLess(sent.index("GroupDN"), sent.index("PartitionDN"))

    def test_auto_derives_partition_dn_from_identity(self):
        client = _build_cap_client("AccountManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetADGroupMemberResponse><ca:Members/></ca:GetADGroupMemberResponse>'
        )
        client.get_ad_group_member(
            "CN=Admins,CN=Users,DC=example,DC=local",
        )
        sent = client._nmf.send.call_args[0][0]
        self.assertIn("<ca:PartitionDN>DC=example,DC=local</ca:PartitionDN>", sent)

    def test_parses_members_with_decoded_sid(self):
        client = _build_cap_client("AccountManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetADGroupMemberResponse>'
            '<ca:Members xmlns:i="http://www.w3.org/2001/XMLSchema-instance">'
            '<ca:ActiveDirectoryPrincipal>'
            '<ca:DistinguishedName>CN=alice,CN=Users,DC=example,DC=local</ca:DistinguishedName>'
            '<ca:Name>alice</ca:Name>'
            '<ca:ObjectClass>user</ca:ObjectClass>'
            '<ca:ObjectGuid>e7d808c7-b439-40f7-b061-a09ddb843dab</ca:ObjectGuid>'
            '<ca:ObjectTypes xmlns:b="http://schemas.microsoft.com/2003/10/Serialization/Arrays">'
            '<b:string>top</b:string><b:string>person</b:string><b:string>user</b:string>'
            '</ca:ObjectTypes>'
            '<ca:ReferenceServer>example.local</ca:ReferenceServer>'
            f'<ca:SID>{_sid_b64("S-1-5-21-1-2-3-500")}</ca:SID>'
            '<ca:SamAccountName>alice</ca:SamAccountName>'
            '</ca:ActiveDirectoryPrincipal>'
            '</ca:Members></ca:GetADGroupMemberResponse>'
        )
        members = client.get_ad_group_member(
            "CN=Admins,CN=Users,DC=example,DC=local",
            partition_dn="DC=example,DC=local",
        )
        self.assertEqual(len(members), 1)
        m = members[0]
        self.assertEqual(m["Name"], "alice")
        self.assertEqual(m["ObjectClass"], "user")
        self.assertEqual(m["ObjectTypes"], ["top", "person", "user"])
        self.assertEqual(m["SID"], "S-1-5-21-1-2-3-500")
        self.assertEqual(m["ReferenceServer"], "example.local")
        # ActiveDirectoryPrincipal does not carry GroupScope/GroupType.
        self.assertNotIn("GroupScope", m)
        self.assertNotIn("GroupType", m)

    def test_empty_wrapper_returns_empty_list(self):
        client = _build_cap_client("AccountManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetADGroupMemberResponse><ca:Members/></ca:GetADGroupMemberResponse>'
        )
        self.assertEqual(
            client.get_ad_group_member(
                "CN=g,CN=Users,DC=example,DC=local",
                partition_dn="DC=example,DC=local",
            ),
            [],
        )

    def test_fault_surfaces_as_error_dict(self):
        client = _build_cap_client("AccountManagement")
        client._nmf.recv.return_value = _fault_envelope()
        result = client.get_ad_group_member(
            "CN=g,CN=Users,DC=example,DC=local",
            partition_dn="DC=example,DC=local",
        )
        self.assertIsInstance(result, dict)
        self.assertIn("error", result)


class GetADPrincipalGroupMembershipTests(unittest.TestCase):
    """GetADPrincipalGroupMembership — identity field <PrincipalDN>;
    alphabetical order flips to FormatOffered < PartitionDN <
    PrincipalDN; response wrapper <MemberOf>, items
    <ActiveDirectoryGroup> (with extra GroupScope/GroupType)."""

    def test_body_sends_principal_dn_after_partition_dn(self):
        client = _build_cap_client("AccountManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetADPrincipalGroupMembershipResponse><ca:MemberOf/>'
            '</ca:GetADPrincipalGroupMembershipResponse>'
        )
        client.get_ad_principal_group_membership(
            "CN=alice,CN=Users,DC=example,DC=local",
            partition_dn="DC=example,DC=local",
        )
        sent = client._nmf.send.call_args[0][0]
        self.assertIn(
            "AccountManagement/GetADPrincipalGroupMembership</a:Action>", sent,
        )
        self.assertIn(
            "<ca:PrincipalDN>CN=alice,CN=Users,DC=example,DC=local</ca:PrincipalDN>",
            sent,
        )
        self.assertLess(sent.index("PartitionDN"), sent.index("PrincipalDN"))

    def test_parses_group_entries_with_scope_and_type(self):
        client = _build_cap_client("AccountManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetADPrincipalGroupMembershipResponse>'
            '<ca:MemberOf xmlns:i="http://www.w3.org/2001/XMLSchema-instance">'
            '<ca:ActiveDirectoryGroup>'
            '<ca:DistinguishedName>CN=Domain Users,CN=Users,DC=example,DC=local</ca:DistinguishedName>'
            '<ca:Name>Domain Users</ca:Name>'
            '<ca:ObjectClass>group</ca:ObjectClass>'
            '<ca:ObjectGuid>b527cac1-c989-4791-8893-40e956241978</ca:ObjectGuid>'
            '<ca:ObjectTypes xmlns:b="http://schemas.microsoft.com/2003/10/Serialization/Arrays">'
            '<b:string>top</b:string><b:string>group</b:string>'
            '</ca:ObjectTypes>'
            '<ca:ReferenceServer>example.local</ca:ReferenceServer>'
            f'<ca:SID>{_sid_b64("S-1-5-21-1-2-3-513")}</ca:SID>'
            '<ca:SamAccountName>Domain Users</ca:SamAccountName>'
            '<ca:GroupScope>Global</ca:GroupScope>'
            '<ca:GroupType>Security</ca:GroupType>'
            '</ca:ActiveDirectoryGroup>'
            '</ca:MemberOf></ca:GetADPrincipalGroupMembershipResponse>'
        )
        groups = client.get_ad_principal_group_membership(
            "CN=alice,CN=Users,DC=example,DC=local",
            partition_dn="DC=example,DC=local",
        )
        self.assertEqual(len(groups), 1)
        g = groups[0]
        self.assertEqual(g["Name"], "Domain Users")
        self.assertEqual(g["GroupScope"], "Global")
        self.assertEqual(g["GroupType"], "Security")
        self.assertEqual(g["SID"], "S-1-5-21-1-2-3-513")


class GetADPrincipalAuthorizationGroupTests(unittest.TestCase):
    """GetADPrincipalAuthorizationGroup — same identity field and body
    alphabetical order as GetADPrincipalGroupMembership. Spec names the
    response wrapper <AuthorizationGroups>; Windows Server 2025 (build
    26100) actually emits <MemberOf>; both are accepted. Also exercises
    well-known SIDs (Everyone / Authenticated Users) which come with nil
    DistinguishedName / ObjectClass — these must surface as explicit
    None in the dict (schema-stable JSON)."""

    def test_body_targets_authorization_group_action(self):
        client = _build_cap_client("AccountManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetADPrincipalAuthorizationGroupResponse>'
            '<ca:MemberOf/></ca:GetADPrincipalAuthorizationGroupResponse>'
        )
        client.get_ad_principal_authorization_group(
            "CN=alice,CN=Users,DC=example,DC=local",
            partition_dn="DC=example,DC=local",
        )
        sent = client._nmf.send.call_args[0][0]
        self.assertIn(
            "AccountManagement/GetADPrincipalAuthorizationGroup</a:Action>", sent,
        )

    def test_parses_under_memberof_wrapper_with_well_known_sids(self):
        client = _build_cap_client("AccountManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetADPrincipalAuthorizationGroupResponse>'
            '<ca:MemberOf xmlns:i="http://www.w3.org/2001/XMLSchema-instance">'
            # Well-known SID: nil DN/ObjectClass; empty ObjectTypes; zero-GUID;
            # SamAccountName populated with friendly name.
            '<ca:ActiveDirectoryGroup>'
            '<ca:DistinguishedName i:nil="true"/>'
            '<ca:Name>Everyone</ca:Name>'
            '<ca:ObjectClass i:nil="true"/>'
            '<ca:ObjectGuid>00000000-0000-0000-0000-000000000000</ca:ObjectGuid>'
            '<ca:ObjectTypes xmlns:b="http://schemas.microsoft.com/2003/10/Serialization/Arrays">'
            '</ca:ObjectTypes>'
            '<ca:ReferenceServer>example.local</ca:ReferenceServer>'
            f'<ca:SID>{_sid_b64("S-1-1-0")}</ca:SID>'
            '<ca:SamAccountName>Everyone</ca:SamAccountName>'
            '<ca:GroupScope>DomainLocal</ca:GroupScope>'
            '<ca:GroupType>Security</ca:GroupType>'
            '</ca:ActiveDirectoryGroup>'
            # Normal AD group, all fields populated.
            '<ca:ActiveDirectoryGroup>'
            '<ca:DistinguishedName>CN=Domain Users,CN=Users,DC=example,DC=local</ca:DistinguishedName>'
            '<ca:Name>Domain Users</ca:Name>'
            '<ca:ObjectClass>group</ca:ObjectClass>'
            '<ca:ObjectGuid>b527cac1-c989-4791-8893-40e956241978</ca:ObjectGuid>'
            '<ca:ObjectTypes xmlns:b="http://schemas.microsoft.com/2003/10/Serialization/Arrays">'
            '<b:string>top</b:string><b:string>group</b:string>'
            '</ca:ObjectTypes>'
            '<ca:ReferenceServer>example.local</ca:ReferenceServer>'
            f'<ca:SID>{_sid_b64("S-1-5-21-1-2-3-513")}</ca:SID>'
            '<ca:SamAccountName>Domain Users</ca:SamAccountName>'
            '<ca:GroupScope>Global</ca:GroupScope>'
            '<ca:GroupType>Security</ca:GroupType>'
            '</ca:ActiveDirectoryGroup>'
            '</ca:MemberOf></ca:GetADPrincipalAuthorizationGroupResponse>'
        )
        groups = client.get_ad_principal_authorization_group(
            "CN=alice,CN=Users,DC=example,DC=local",
            partition_dn="DC=example,DC=local",
        )
        self.assertEqual(len(groups), 2)

        everyone, dom_users = groups

        # Well-known SID: nil scalars surface as explicit None (not absent),
        # empty ObjectTypes wrapper → [].
        self.assertEqual(everyone["Name"], "Everyone")
        self.assertEqual(everyone["SID"], "S-1-1-0")
        self.assertIn("DistinguishedName", everyone)
        self.assertIsNone(everyone["DistinguishedName"])
        self.assertIsNone(everyone["ObjectClass"])
        self.assertEqual(everyone["SamAccountName"], "Everyone")
        self.assertEqual(everyone["GroupScope"], "DomainLocal")
        self.assertEqual(everyone["ObjectTypes"], [])

        # Normal AD group: all fields populated.
        self.assertEqual(
            dom_users["DistinguishedName"],
            "CN=Domain Users,CN=Users,DC=example,DC=local",
        )
        self.assertEqual(dom_users["GroupScope"], "Global")
        self.assertEqual(dom_users["SID"], "S-1-5-21-1-2-3-513")
        self.assertEqual(dom_users["ObjectTypes"], ["top", "group"])

    def test_parses_under_spec_authorization_groups_wrapper(self):
        """Spec-conformant wrapper name must still parse (forward-compat)."""
        client = _build_cap_client("AccountManagement")
        client._nmf.recv.return_value = _wrap_envelope(
            '<ca:GetADPrincipalAuthorizationGroupResponse>'
            '<ca:AuthorizationGroups xmlns:i="http://www.w3.org/2001/XMLSchema-instance">'
            '<ca:ActiveDirectoryGroup>'
            '<ca:Name>Users</ca:Name>'
            '<ca:ObjectClass>group</ca:ObjectClass>'
            f'<ca:SID>{_sid_b64("S-1-5-32-545")}</ca:SID>'
            '<ca:GroupScope>DomainLocal</ca:GroupScope>'
            '</ca:ActiveDirectoryGroup>'
            '</ca:AuthorizationGroups></ca:GetADPrincipalAuthorizationGroupResponse>'
        )
        groups = client.get_ad_principal_authorization_group(
            "CN=alice,CN=Users,DC=example,DC=local",
            partition_dn="DC=example,DC=local",
        )
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["Name"], "Users")
        self.assertEqual(groups[0]["SID"], "S-1-5-32-545")


class FormatPrincipalListPowershellTests(unittest.TestCase):
    """Verify the PowerShell-style Format-List renderer used by the 3
    AccountManagement dispatch paths in src/soaphound/soaphound.py.
    """

    def test_two_principals_block_alignment_and_list_rendering(self):
        principals = [
            {
                "DistinguishedName": "CN=Administrator,CN=Users,DC=example,DC=local",
                "Name": "Administrator",
                "ObjectClass": "user",
                "ObjectTypes": ["top", "person", "organizationalPerson", "user"],
                "SID": "S-1-5-21-1-2-3-500",
            },
            {
                "DistinguishedName": "CN=Domain Users,CN=Users,DC=example,DC=local",
                "Name": "Domain Users",
                "ObjectClass": "group",
                "ObjectTypes": ["top", "group"],
                "SID": "S-1-5-21-1-2-3-513",
            },
        ]
        out = _format_principal_list_powershell(principals)
        # Blocks separated by exactly one blank line.
        self.assertIn("\n\n", out)
        blocks = out.split("\n\n")
        self.assertEqual(len(blocks), 2)
        # Colon aligned on longest key per block (DistinguishedName = 17).
        self.assertIn("DistinguishedName : CN=Administrator,CN=Users,DC=example,DC=local", blocks[0])
        self.assertIn("Name              : Administrator", blocks[0])
        # ObjectTypes rendered as PowerShell-style braced list.
        self.assertIn("ObjectTypes       : {top, person, organizationalPerson, user}", blocks[0])
        self.assertIn("ObjectTypes       : {top, group}", blocks[1])
        # Trailing block has no extra blank line.
        self.assertFalse(out.endswith("\n"))

    def test_well_known_none_values_render_as_empty_string(self):
        principals = [
            {
                "DistinguishedName": None,
                "Name": "Everyone",
                "ObjectClass": None,
                "ObjectTypes": [],
                "SID": "S-1-1-0",
            },
        ]
        out = _format_principal_list_powershell(principals)
        # None → empty string on the right of the colon, never the literal "None".
        self.assertIn("DistinguishedName : \n", out + "\n")
        self.assertIn("ObjectClass       : \n", out + "\n")
        self.assertNotIn(": None", out)
        # Empty list renders as "{}".
        self.assertIn("ObjectTypes       : {}", out)
        # Populated string field still renders plainly.
        self.assertIn("Name              : Everyone", out)
        self.assertIn("SID               : S-1-1-0", out)


if __name__ == "__main__":
    unittest.main()
