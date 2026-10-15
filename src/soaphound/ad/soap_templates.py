NAMESPACES = {
    "ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
    "addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
    "adlq": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery",
    "da": "http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess",
    "ca": "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions",
    # MS-ADCAP TopologyManagement capability namespace.
    "tm": "http://schemas.microsoft.com/2008/1/ActiveDirectory/TopologyManagement",

    "soapenv": "http://www.w3.org/2003/05/soap-envelope",
    "wsa": "http://www.w3.org/2005/08/addressing",
    "wsen": "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
    "wxf": "http://schemas.xmlsoap.org/ws/2004/09/transfer",
    "xsd": "http://www.w3.org/2001/XMLSchema",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",

    "s": "http://www.w3.org/2003/05/soap-envelope",
    "a": "http://www.w3.org/2005/08/addressing",
}


LDAP_ROOT_DSE_FSTRING: str = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
    xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<s:Header>
    <a:Action s:mustUnderstand="1" xmlns="http://www.w3.org/2005/08/addressing">http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>
    <ad:instance>ldap:389</ad:instance>
    <ad:objectReferenceProperty>11111111-1111-1111-1111-111111111111</ad:objectReferenceProperty>
    <a:MessageID>urn:uuid:{uuid}</a:MessageID>
    <a:ReplyTo>
        <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Resource</a:To>
</s:Header>
    <s:Body></s:Body>
</s:Envelope>"""


LDAP_QUERY_FSTRING: str = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
    xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</a:Action>
        <ad:instance>ldap:389</ad:instance>
        <a:MessageID>urn:uuid:{uuid}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To>
    </s:Header>
    <s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
        xmlns:adlq="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery">
        <wsen:Enumerate>
            <wsen:Filter Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery">
                <adlq:LdapQuery>
                    <adlq:Filter>{query}</adlq:Filter>
                    <adlq:BaseObject>{baseobj}</adlq:BaseObject>
                    <adlq:Scope>Subtree</adlq:Scope>
                </adlq:LdapQuery>
            </wsen:Filter>
            <ad:Selection Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1">
                {attributes}
            </ad:Selection>
        </wsen:Enumerate>
    </s:Body>
</s:Envelope>"""

LDAP_PULL_FSTRING: str = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
    xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull</a:Action>
        <ad:instance>ldap:389</ad:instance>
        <a:MessageID>urn:uuid:{uuid}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To>
    </s:Header>
    <s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
        <wsen:Pull>
            <wsen:EnumerationContext>{enum_ctx}</wsen:EnumerationContext>
            <wsen:MaxElements>256</wsen:MaxElements>
                <ad:controls>
                    <ad:control criticality="true" type="1.2.840.113556.1.4.801">
                       <ad:controlValue xsi:type="xsd:base64Binary">MIQAAAADAgEH</ad:controlValue>
                </ad:control>
        </wsen:Pull>
    </s:Body>
</s:Envelope>"""


# ---------------------------------------------------------------------------
# MS-ADCAP TopologyManagement templates
# ---------------------------------------------------------------------------
# Three primitive messages against the TopologyManagement capability endpoint
# at net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/TopologyManagement.
# Action URIs come from MS-ADCAP section 3.2.4. All three share the same
# WS-Addressing + SOAP 1.2 envelope used by the Enumeration and Resource
# templates above; only the Action header and body change.
#
# NOTE: these templates are minimal payloads intended for the three use cases
# the Linux offensive tooling world does not currently cover (GetADForest,
# TranslateName, ChangeOptionalFeature). Richer field sets (site topology,
# optional feature state) can be added later without touching the dispatch.

TM_GET_AD_FOREST_FSTRING: str = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:tm="http://schemas.microsoft.com/2008/1/ActiveDirectory/TopologyManagement">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/2008/1/ActiveDirectory/TopologyManagement/GetADForest</a:Action>
        <a:MessageID>urn:uuid:{uuid}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/TopologyManagement</a:To>
    </s:Header>
    <s:Body>
        <tm:GetADForest>
            <tm:forestFQDN>{domain}</tm:forestFQDN>
        </tm:GetADForest>
    </s:Body>
</s:Envelope>"""

TM_TRANSLATE_NAME_FSTRING: str = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:tm="http://schemas.microsoft.com/2008/1/ActiveDirectory/TopologyManagement">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/2008/1/ActiveDirectory/TopologyManagement/TranslateName</a:Action>
        <a:MessageID>urn:uuid:{uuid}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/TopologyManagement</a:To>
    </s:Header>
    <s:Body>
        <tm:TranslateName>
            <tm:names><tm:string>{name}</tm:string></tm:names>
            <tm:formatOffered>{format_offered}</tm:formatOffered>
            <tm:formatDesired>{format_desired}</tm:formatDesired>
        </tm:TranslateName>
    </s:Body>
</s:Envelope>"""

TM_CHANGE_OPTIONAL_FEATURE_FSTRING: str = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:tm="http://schemas.microsoft.com/2008/1/ActiveDirectory/TopologyManagement">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/2008/1/ActiveDirectory/TopologyManagement/ChangeOptionalFeature</a:Action>
        <a:MessageID>urn:uuid:{uuid}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/TopologyManagement</a:To>
    </s:Header>
    <s:Body>
        <tm:ChangeOptionalFeature>
            <tm:featureID>{feature_guid}</tm:featureID>
            <tm:enable>{enable_bool}</tm:enable>
        </tm:ChangeOptionalFeature>
    </s:Body>
</s:Envelope>"""


LDAP_PUT_FSTRING: str = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
        xmlns:a="http://www.w3.org/2005/08/addressing"
        xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
        xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:da="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess">
        <s:Header>
            <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/transfer/Put</a:Action>
            <ad:instance>ldap:389</ad:instance>
            <ad:objectReferenceProperty>{object_ref}</ad:objectReferenceProperty>
            <da:IdentityManagementOperation s:mustUnderstand="1"
                xmlns:i="http://www.w3.org/2001/XMLSchema-instance"></da:IdentityManagementOperation>
            <a:MessageID>urn:uuid:{uuid}</a:MessageID>
            <a:ReplyTo>
                <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
            </a:ReplyTo>
            <a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Resource</a:To>
        </s:Header>
        <s:Body>
            <da:ModifyRequest Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1">
                <da:Change Operation="{operation}">
                    <da:AttributeType>{attribute}</da:AttributeType>
                    <da:AttributeValue>
                        <ad:value xsi:type="xsd:{data_type}">{value}</ad:value>
                    </da:AttributeValue>
                </da:Change>
            </da:ModifyRequest>
        </s:Body>
    </s:Envelope>"""
