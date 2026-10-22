import pytest
from unittest.mock import MagicMock

from soaphound.ad.writers import (
    ws_transfer_create,
    ws_transfer_put,
    ws_transfer_delete,
)


def test_ws_transfer_create_renders_template():
    client = MagicMock()
    client.send.return_value = None
    client.recv.return_value = "<s:Envelope>...success...</s:Envelope>"
    ws_transfer_create(client, "dc.jjk.local", "CN=test,OU=X,DC=jjk,DC=local", "test$")
    sent = client.send.call_args[0][0]
    assert "transfer/Create" in sent
    assert "IdentityManagementOperation" in sent
    assert 'Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1"' in sent
    assert "AttributeTypeAndValue" in sent
    assert "msDS-DelegatedManagedServiceAccount" in sent
    assert "test$" in sent
    assert "CN=test" in sent
    assert "OU=X,DC=jjk,DC=local" in sent  # container


def test_ws_transfer_delete_renders_template():
    client = MagicMock()
    client.recv.return_value = "<s:Envelope>...success...</s:Envelope>"
    ws_transfer_delete(client, "dc.jjk.local", "CN=test,OU=X,DC=jjk,DC=local")
    sent = client.send.call_args[0][0]
    assert "transfer/Delete" in sent
    assert "CN=test,OU=X,DC=jjk,DC=local" in sent
    assert "/Windows/Resource" in sent


def test_ws_transfer_put_delegates_to_adws_connect():
    adws = MagicMock()
    adws.put.return_value = True
    ws_transfer_put(adws, "CN=x,DC=y", "description", "hello")
    adws.put.assert_called_once_with("CN=x,DC=y", "replace", "description", "string", "hello")


def test_special_chars_dn_rendering():
    """Spaces and parentheses in the CN survive the DN -> CN+container
    split cleanly. NB: a literal comma inside a CN would require RFC 4514
    escaping and a proper DN parser; the current .partition(",") splitter
    does not handle that case and such DNs are out of scope for v1.5.0.
    """
    client = MagicMock()
    client.send.return_value = None
    client.recv.return_value = "<s:Envelope>...success...</s:Envelope>"
    ws_transfer_create(
        client,
        "dc.jjk.local",
        "CN=svc (web prod),OU=X,DC=jjk,DC=local",
        "svc-web$",
    )
    sent = client.send.call_args[0][0]
    assert "CN=svc (web prod)" in sent
    assert "OU=X,DC=jjk,DC=local" in sent
    assert "svc-web$" in sent


def test_insufficient_access_rights_raises_permission_error():
    client = MagicMock()
    client.recv.return_value = "<s:Fault><s:Code>insufficientAccessRights</s:Code></s:Fault>"
    with pytest.raises(PermissionError):
        ws_transfer_create(client, "dc", "CN=x", "x$")
