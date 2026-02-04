# Description
While reading [Bloodhound.py](https://github.com/dirkjanm/BloodHound.py), a Linux alternative to [Sharphound](https://github.com/SpecterOps/SharpHound), we observed that object collection is performed on a case-by-case basis. Specific conditions are evaluated to determine the most relevant information for each collected object, and tailored actions are taken accordingly.

We sought to follow a similar logic while implementing Soaphound.py, aiming to collect the most valuable information during object enumeration through ADWS. In addition, as users' session on machines are not collected throught LDAP, we reused Bloodhound.py way to perform this collect. 

The tool is currently being improved to cover all specific data collection scenarios. At the time of writing, it is capable of collecting Active Directory objects via the ADWS service and retrieving remote session data similar to what BloodHound.py achieves. Alternatively, it can operate in a mode restricted to collecting only AD objects through ADWS (using option -c ADWSOnly). 

More informations: [you may check out the short blog post](https://j4s0nmo0n.github.io/belettetimoree.github.io/Soaphound.py%20-%20Collecting%20Active%20Directory%20Objects%20over%20ADWS%20from%20Linux.html)

# Usage
```
usage: soaphound [-h] [-c COLLECTIONMETHOD] -d DOMAIN [-v] [--ts] -u USERNAME [-p PASSWORD] [--hashes HASHES] -dc HOST [--zip] [-op PREFIX_NAME] [-wk NUM_WORKERS] [--output-dir OUTPUT_DIR]

Python based ingestor for BloodHound using ADWS

options:
  -h, --help            show this help message and exit
  -c COLLECTIONMETHOD, --collectionmethod COLLECTIONMETHOD
                        Which information to collect : Default or ADWSOnly (no computer connections).
  -d DOMAIN, --domain DOMAIN
                        Domain to query.
  -v                    Enable verbose output.
  --ts                  Add timestamp to logs.

authentication options:
  NTLM is the only method supported at the moment.

  -u USERNAME, --username USERNAME
                        Username. Format: username[@domain]; If the domain is unspecified, the current domain is used.
  -p PASSWORD, --password PASSWORD
                        Password
  --hashes HASHES       LM:NLTM hashes

collection options:
  -dc HOST, --domain-controller HOST
                        DC to query (hostname)
  --zip                 Compress the JSON output files into a zip archive.
  -op PREFIX_NAME, --outputprefix PREFIX_NAME
                        String to prepend to output file names.
  -wk NUM_WORKERS, --worker_num NUM_WORKERS
                        Number of workers, default 100
  --output-dir OUTPUT_DIR
                        Output folder (default .).
```

# Installation
With `poetry`

```
poetry install
```

# Example Usage

Perform ADWS collection with session enumerations 

```
poetry run soaphound -d <domain> -u <user> -p <password> -dc <dc-ip> --output-dir output
```

Perform only ADWS collection

```
poetry run soaphound -d <domain> -u <user> -p <password> -dc <dc-ip> --output-dir output -c ADWSOnly
```



# References

- [Falcon Force Team](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/) for the initial inspiration.
- [Bloodhound.py](https://github.com/dirkjanm/BloodHound.py), for this amazing implementation of Bloodhound ingestor.
- [Microsoft](https://learn.microsoft.com/en-us/openspecs/windows_psrotocols/ms-addm/59205cf6-aa8e-4f7e-be57-8b63640bf9a4) for the official protocol documentation.
- [ERNW](https://insinuator.net/2016/08/pentesting-webservices-with-net-tcp-binding/) for the initial boost.
- [X-force Red](https://www.ibm.com/think/x-force/stealthy-enumeration-of-active-directory-environments-through-adws) for their brilliant implementation of NBFX and research insights.
- [Rabobank red team](https://rabobank.jobs/en/techblog/adws-an-unconventional-path-into-active-directory-luc-kolen/) for sharing valuable resources and operational insights.

