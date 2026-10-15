"""Unit tests for the MS-ADCAP TopologyManagement primitives.

These tests exercise ADWSConnect.get_ad_forest, translate_name and
change_optional_feature. No actual ADWS connection is opened: an ADWSConnect
instance is built via object.__new__ and _nmf is replaced by a MagicMock, so
.send() captures the SOAP payload for inspection and .recv() returns a fake
server reply.
"""
import re
import unittest
from unittest.mock import MagicMock

from soaphound.ad.adws import ADWSConnect
from soaphound.ad.soap_templates import NAMESPACES


_TM_NS = NAMESPACES["tm"]


def _build_tm_client() -> ADWSConnect:
    """Return an ADWSConnect instance wired as a TopologyManagement client,
    with _nmf replaced by a MagicMock. No real socket is opened."""
    client = object.__new__(ADWSConnect)
    client._fqdn = "dc.example.local"
    client._domain = "example.local"
    client._username = "svc"
    client._auth = None
    client._resource = "TopologyManagement"
    client._nmf = MagicMock()
    return client


def _wrap_envelope(body_xml: str) -> str:
    """Build a minimal SOAP 1.2 reply envelope around a tm:* body fragment."""
    return (
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        f'xmlns:tm="{_TM_NS}">'
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
        client = _build_tm_client()
        client._nmf.recv.return_value = _wrap_envelope(
            '<tm:GetADForestResponse>'
            '<tm:GetADForestResult>'
            '<tm:Name>example.local</tm:Name>'
            '<tm:ForestMode>Windows2016Forest</tm:ForestMode>'
            '<tm:RootDomain>example.local</tm:RootDomain>'
            '</tm:GetADForestResult>'
            '</tm:GetADForestResponse>'
        )

        result = client.get_ad_forest()

        sent = client._nmf.send.call_args[0][0]
        self.assertIn("TopologyManagement/GetADForest</a:Action>", sent)
        self.assertIn("<tm:GetADForest>", sent)
        self.assertIn("<tm:forestFQDN>example.local</tm:forestFQDN>", sent)
        self.assertIn(f'net.tcp://dc.example.local:9389/ActiveDirectoryWebServices/Windows/TopologyManagement', sent)

        self.assertEqual(result.get("Name"), "example.local")
        self.assertEqual(result.get("ForestMode"), "Windows2016Forest")
        self.assertEqual(result.get("RootDomain"), "example.local")

    def test_translate_name_sends_right_template_and_parses_reply(self):
        client = _build_tm_client()
        client._nmf.recv.return_value = _wrap_envelope(
            '<tm:TranslateNameResponse>'
            '<tm:TranslateNameResult>'
            '<tm:string>CN=svc,OU=Users,DC=example,DC=local</tm:string>'
            '</tm:TranslateNameResult>'
            '</tm:TranslateNameResponse>'
        )

        result = client.translate_name("EXAMPLE\\svc", format_offered=2, format_desired=1)

        sent = client._nmf.send.call_args[0][0]
        self.assertIn("TopologyManagement/TranslateName</a:Action>", sent)
        self.assertIn("<tm:TranslateName>", sent)
        self.assertIn("<tm:string>EXAMPLE\\svc</tm:string>", sent)
        self.assertIn("<tm:formatOffered>2</tm:formatOffered>", sent)
        self.assertIn("<tm:formatDesired>1</tm:formatDesired>", sent)

        self.assertEqual(result["input"], "EXAMPLE\\svc")
        self.assertEqual(result["format_offered"], 2)
        self.assertEqual(result["format_desired"], 1)
        self.assertEqual(result["translated"], ["CN=svc,OU=Users,DC=example,DC=local"])

    def test_change_optional_feature_sends_right_template_and_parses_reply(self):
        client = _build_tm_client()
        client._nmf.recv.return_value = _wrap_envelope(
            '<tm:ChangeOptionalFeatureResponse/>'
        )

        guid = "766ddcd8-acd0-445e-f3b9-a7f9b6744f2a"  # Recycle Bin
        result = client.change_optional_feature(guid, enable=True)

        sent = client._nmf.send.call_args[0][0]
        self.assertIn("TopologyManagement/ChangeOptionalFeature</a:Action>", sent)
        self.assertIn("<tm:ChangeOptionalFeature>", sent)
        self.assertIn(f"<tm:featureID>{guid}</tm:featureID>", sent)
        self.assertIn("<tm:enable>true</tm:enable>", sent)

        self.assertEqual(result, {"feature_guid": guid, "enable": True, "result": "ok"})

    def test_fault_returned_as_error_dict_not_raised(self):
        """A SOAP Fault (e.g. AccessDenied) is reported as a plain error dict
        so callers can switch on it instead of handling exceptions."""
        client = _build_tm_client()
        client._nmf.recv.return_value = _fault_envelope(reason="AccessDenied", detail="yuji is non-privileged")

        result = client.change_optional_feature("00000000-0000-0000-0000-000000000000", enable=True)

        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("error"), "AccessDenied")
        self.assertIn("yuji is non-privileged", result.get("detail", ""))

    def test_methods_refuse_non_topology_client(self):
        """Calling a TopologyManagement primitive on a client that was not
        opened against that endpoint must raise NotImplementedError."""
        client = _build_tm_client()
        client._resource = "Enumeration"
        with self.assertRaises(NotImplementedError):
            client.get_ad_forest()
        with self.assertRaises(NotImplementedError):
            client.translate_name("foo")
        with self.assertRaises(NotImplementedError):
            client.change_optional_feature("00000000-0000-0000-0000-000000000000")
        client._nmf.send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
