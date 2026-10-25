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

from soaphound.ad.adws import ADWSConnect, _ad_name_format_name
from soaphound.ad.soap_templates import NAMESPACES


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


if __name__ == "__main__":
    unittest.main()
