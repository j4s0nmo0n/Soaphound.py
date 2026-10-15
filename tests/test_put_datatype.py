"""Unit tests for ADWSConnect.put() data_type handling.

These tests exercise the normalisation and validation added to put() so that
passing a legacy 'xsd:' prefix no longer produces a malformed xsi:type on the
wire. The ADWS connection is never actually opened: an ADWSConnect instance
is built via object.__new__ and _nmf is replaced by a MagicMock so send()
captures the SOAP payload for inspection.
"""
import re
import unittest
from unittest.mock import MagicMock

from soaphound.ad.adws import ADWSConnect


# Minimal SOAP envelope accepted by _handle_str_to_xml / put(): must contain
# </s:Envelope> and a <s:Body> whose child is <wxf:PutResponse/> so put() reads
# the write as a success and returns True.
_FAKE_PUT_RESPONSE = (
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:wxf="http://schemas.xmlsoap.org/ws/2004/09/transfer">'
    '<s:Header/>'
    '<s:Body><wxf:PutResponse/></s:Body>'
    '</s:Envelope>'
)


def _build_resource_client() -> ADWSConnect:
    """Return an ADWSConnect instance wired as a Resource client, with _nmf
    replaced by a MagicMock. No real socket is opened."""
    client = object.__new__(ADWSConnect)
    client._fqdn = "dc.example.local"
    client._domain = "example.local"
    client._username = "svc"
    client._auth = None
    client._resource = "Resource"
    nmf = MagicMock()
    nmf.recv.return_value = _FAKE_PUT_RESPONSE
    client._nmf = nmf
    return client


def _xsi_type_values(soap_payload: str) -> list[str]:
    """Return every value found for xsi:type in the given SOAP payload."""
    return re.findall(r'xsi:type="([^"]+)"', soap_payload)


class PutDataTypeTests(unittest.TestCase):
    def test_put_strips_xsd_prefix(self):
        """A legacy 'xsd:string' input is stripped to 'string' before the
        template adds its own 'xsd:' prefix: the on-wire xsi:type must be
        'xsd:string' exactly once, never 'xsd:xsd:string'."""
        client = _build_resource_client()
        ok = client.put(
            object_ref="CN=canary,DC=example,DC=local",
            operation="replace",
            attribute="description",
            data_type="xsd:string",
            value="legacy-prefix-input",
        )
        self.assertTrue(ok)
        sent = client._nmf.send.call_args[0][0]
        xsi_values = _xsi_type_values(sent)
        self.assertEqual(xsi_values, ["xsd:string"], f"got xsi:type values: {xsi_values!r}")
        self.assertNotIn("xsd:xsd:string", sent)

    def test_put_accepts_bare_datatype(self):
        """The documented form data_type='string' produces the same xsi:type
        value and reaches the server unchanged."""
        client = _build_resource_client()
        ok = client.put(
            object_ref="CN=canary,DC=example,DC=local",
            operation="replace",
            attribute="description",
            data_type="string",
            value="bare-input",
        )
        self.assertTrue(ok)
        sent = client._nmf.send.call_args[0][0]
        self.assertEqual(_xsi_type_values(sent), ["xsd:string"])

    def test_put_rejects_unknown_datatype(self):
        """A value outside the allow-list must raise ValueError before any
        network call is attempted."""
        client = _build_resource_client()
        with self.assertRaises(ValueError) as ctx:
            client.put(
                object_ref="CN=canary,DC=example,DC=local",
                operation="replace",
                attribute="description",
                data_type="foo",
                value="whatever",
            )
        self.assertIn("Unsupported data_type", str(ctx.exception))
        client._nmf.send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
