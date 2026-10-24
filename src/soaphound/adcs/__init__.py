"""AD CS enrollment primitives over SOAP (MS-XCEP + MS-WSTEP).

These modules reach the AD Certificate Services enrollment endpoints
over HTTPS (/ADPolicyProvider_CEP_Kerberos and /<ca>_CES_Kerberos) with
Kerberos authentication, so they are strictly out of band from the ADWS
collect pipeline (net.tcp:9389) that the rest of the package drives.

Entry points:
    * xcep.get_policies       — MS-XCEP GetPolicies (template + CA bundle)
    * wstep.request_cert      — MS-WSTEP RequestSecurityToken (issue cert)
    * wstep.run_enroll        — XCEP -> CSR -> WSTEP -> PFX orchestration
    * xcep.run_list_policies  — CLI dispatch for --list-policies-ws
"""
