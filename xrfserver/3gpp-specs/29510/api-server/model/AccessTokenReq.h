/**
* NRF NFManagement Service
* NRF NFManagement Service. © 2021, 3GPP Organizational Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved. 
*
* The version of the OpenAPI document: 1.2.0-alpha.5
* 
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/
/*
 * AccessTokenReq.h
 *
 * Contains information related to the access token request
 */

#ifndef AccessTokenReq_H_
#define AccessTokenReq_H_


#include "NFType.h"
#include "PlmnIdNid.h"
#include <string>
#include "PlmnId.h"
#include "Snssai.h"
#include <vector>
#include <nlohmann/json.hpp>

namespace org::openapitools::server::model
{

/// <summary>
/// Contains information related to the access token request
/// </summary>
class  AccessTokenReq
{
public:
    AccessTokenReq();
    virtual ~AccessTokenReq() = default;


    /// <summary>
    /// Validate the current data in the model. Throws a ValidationException on failure.
    /// </summary>
    void validate() const;

    /// <summary>
    /// Validate the current data in the model. Returns false on error and writes an error
    /// message into the given stringstream.
    /// </summary>
    bool validate(std::stringstream& msg) const;

    /// <summary>
    /// Helper overload for validate. Used when one model stores another model and calls it's validate.
    /// Not meant to be called outside that case.
    /// </summary>
    bool validate(std::stringstream& msg, const std::string& pathPrefix) const;

    bool operator==(const AccessTokenReq& rhs) const;
    bool operator!=(const AccessTokenReq& rhs) const;

    /////////////////////////////////////////////
    /// AccessTokenReq members

    /// <summary>
    /// 
    /// </summary>
    std::string getGrantType() const;
    void setGrantType(std::string const& value);
    /// <summary>
    /// String uniquely identifying a NF instance. The format of the NF Instance ID shall be a Universally Unique Identifier (UUID) version 4, as described in IETF RFC 4122.
    /// </summary>
    std::string getNfInstanceId() const;
    void setNfInstanceId(std::string const& value);
    /// <summary>
    /// 
    /// </summary>
    NFType getNfType() const;
    void setNfType(NFType const& value);
    bool nfTypeIsSet() const;
    void unsetNfType();
    /// <summary>
    /// 
    /// </summary>
    NFType getTargetNfType() const;
    void setTargetNfType(NFType const& value);
    bool targetNfTypeIsSet() const;
    void unsetTargetNfType();
    /// <summary>
    /// 
    /// </summary>
    std::string getScope() const;
    void setScope(std::string const& value);
    /// <summary>
    /// String uniquely identifying a NF instance. The format of the NF Instance ID shall be a Universally Unique Identifier (UUID) version 4, as described in IETF RFC 4122.
    /// </summary>
    std::string getTargetNfInstanceId() const;
    void setTargetNfInstanceId(std::string const& value);
    bool targetNfInstanceIdIsSet() const;
    void unsetTargetNfInstanceId();
    /// <summary>
    /// 
    /// </summary>
    PlmnId getRequesterPlmn() const;
    void setRequesterPlmn(PlmnId const& value);
    bool requesterPlmnIsSet() const;
    void unsetRequesterPlmn();
    /// <summary>
    /// 
    /// </summary>
    std::vector<PlmnId> getRequesterPlmnList() const;
    void setRequesterPlmnList(std::vector<PlmnId> const& value);
    bool requesterPlmnListIsSet() const;
    void unsetRequesterPlmnList();
    /// <summary>
    /// 
    /// </summary>
    std::vector<Snssai> getRequesterSnssaiList() const;
    void setRequesterSnssaiList(std::vector<Snssai> const& value);
    bool requesterSnssaiListIsSet() const;
    void unsetRequesterSnssaiList();
    /// <summary>
    /// Fully Qualified Domain Name
    /// </summary>
    std::string getRequesterFqdn() const;
    void setRequesterFqdn(std::string const& value);
    bool requesterFqdnIsSet() const;
    void unsetRequesterFqdn();
    /// <summary>
    /// 
    /// </summary>
    std::vector<PlmnIdNid> getRequesterSnpnList() const;
    void setRequesterSnpnList(std::vector<PlmnIdNid> const& value);
    bool requesterSnpnListIsSet() const;
    void unsetRequesterSnpnList();
    /// <summary>
    /// 
    /// </summary>
    PlmnId getTargetPlmn() const;
    void setTargetPlmn(PlmnId const& value);
    bool targetPlmnIsSet() const;
    void unsetTargetPlmn();
    /// <summary>
    /// 
    /// </summary>
    std::vector<Snssai> getTargetSnssaiList() const;
    void setTargetSnssaiList(std::vector<Snssai> const& value);
    bool targetSnssaiListIsSet() const;
    void unsetTargetSnssaiList();
    /// <summary>
    /// 
    /// </summary>
    std::vector<std::string> getTargetNsiList() const;
    void setTargetNsiList(std::vector<std::string> const& value);
    bool targetNsiListIsSet() const;
    void unsetTargetNsiList();
    /// <summary>
    /// NF Set Identifier (see clause 28.12 of 3GPP TS 23.003), formatted as the following string \&quot; set&lt;Set ID&gt;.&lt;nftype&gt;set.5gc.mnc&lt;MNC&gt;.mcc&lt;MCC&gt;\&quot;, or \&quot;set&lt;SetID&gt;. &lt;NFType&gt;set.5gc.nid&lt;NID&gt;.mnc&lt;MNC&gt;.mcc&lt;MCC&gt;\&quot; with &lt;MCC&gt; encoded as defined in clause 5.4.2 (\&quot;Mcc\&quot; data type definition) &lt;MNC&gt; encoded as defined in clause 5.4.2 (\&quot;Mnc\&quot; data type definition) &lt;NFType&gt; encoded as a value defined in Table 6.1.6.3.3-1 of 3GPP TS 29.510 but with lower case characters &lt;Set ID&gt; encoded as a string of characters consisting of alphabetic characters (A-Z and a-z), digits (0-9) and/or the hyphen (-) and that shall end with either an alphabetic character or a digit.
    /// </summary>
    std::string getTargetNfSetId() const;
    void setTargetNfSetId(std::string const& value);
    bool targetNfSetIdIsSet() const;
    void unsetTargetNfSetId();
    /// <summary>
    /// NF Service Set Identifier (see clause 28.12 of 3GPP TS 23.003) formatted as the following string  \&quot; set&lt;Set ID&gt;.sn&lt;Service Name&gt;.nfi&lt;NF Instance ID&gt;.5gc.mnc&lt;MNC&gt;.mcc&lt;MCC&gt;\&quot;&gt;\&quot;, or \&quot;set&lt;SetID&gt;.sn&lt;ServiceName&gt;.nfi&lt;NFInstanceID&gt;.5gc.nid&lt;NID&gt;.mnc&lt;MNC&gt;.mcc&lt;MCC&gt;\&quot; with &lt;MCC&gt; encoded as defined in clause 5.4.2 (\&quot;Mcc\&quot; data type definition)  &lt;MNC&gt; encoded as defined in clause 5.4.2 (\&quot;Mnc\&quot; data type definition)  &lt;NID&gt; encoded as defined in clause 5.4.2 (\&quot;Nid\&quot; data type definition) &lt;NFInstanceId&gt; encoded as defined in clause 5.3.2 &lt;ServiceName&gt; encoded as defined in 3GPP TS 29.510 &lt;Set ID&gt; encoded as a string of characters consisting of alphabetic characters (A-Z and a-z), digits (0-9) and/or the hyphen (-) and that shall end with either an alphabetic character or a digit.
    /// </summary>
    std::string getTargetNfServiceSetId() const;
    void setTargetNfServiceSetId(std::string const& value);
    bool targetNfServiceSetIdIsSet() const;
    void unsetTargetNfServiceSetId();
    /// <summary>
    /// String providing an URI formatted according to RFC 3986
    /// </summary>
    std::string getHnrfAccessTokenUri() const;
    void setHnrfAccessTokenUri(std::string const& value);
    bool hnrfAccessTokenUriIsSet() const;
    void unsetHnrfAccessTokenUri();

    friend void to_json(nlohmann::json& j, const AccessTokenReq& o);
    friend void from_json(const nlohmann::json& j, AccessTokenReq& o);
protected:
    std::string m_Grant_type;

    std::string m_NfInstanceId;

    NFType m_NfType;
    bool m_NfTypeIsSet;
    NFType m_TargetNfType;
    bool m_TargetNfTypeIsSet;
    std::string m_Scope;

    std::string m_TargetNfInstanceId;
    bool m_TargetNfInstanceIdIsSet;
    PlmnId m_RequesterPlmn;
    bool m_RequesterPlmnIsSet;
    std::vector<PlmnId> m_RequesterPlmnList;
    bool m_RequesterPlmnListIsSet;
    std::vector<Snssai> m_RequesterSnssaiList;
    bool m_RequesterSnssaiListIsSet;
    std::string m_RequesterFqdn;
    bool m_RequesterFqdnIsSet;
    std::vector<PlmnIdNid> m_RequesterSnpnList;
    bool m_RequesterSnpnListIsSet;
    PlmnId m_TargetPlmn;
    bool m_TargetPlmnIsSet;
    std::vector<Snssai> m_TargetSnssaiList;
    bool m_TargetSnssaiListIsSet;
    std::vector<std::string> m_TargetNsiList;
    bool m_TargetNsiListIsSet;
    std::string m_TargetNfSetId;
    bool m_TargetNfSetIdIsSet;
    std::string m_TargetNfServiceSetId;
    bool m_TargetNfServiceSetIdIsSet;
    std::string m_HnrfAccessTokenUri;
    bool m_HnrfAccessTokenUriIsSet;
    
};

} // namespace org::openapitools::server::model

#endif /* AccessTokenReq_H_ */
