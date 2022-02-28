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
 * SubscriptionData.h
 *
 * Information of a subscription to notifications to NRF events, included in subscription requests and responses
 */

#ifndef SubscriptionData_H_
#define SubscriptionData_H_


#include "NFType.h"
#include "PlmnIdNid.h"
#include <string>
#include "NotificationEventType.h"
#include "OneOfNfInstanceIdCondNfInstanceIdListCondNfTypeCondServiceNameCondServiceNameListCondAmfCondGuamiListCondNetworkSliceCondNfGroupCondNfGroupListCondNfSetCondNfServiceSetCondUpfCondScpDomainCondNwdafCondNefCondDccfCond.h"
#include "PlmnId.h"
#include "PlmnSnssai.h"
#include "Snssai.h"
#include <vector>
#include "NotifCondition.h"
#include <nlohmann/json.hpp>

namespace org::openapitools::server::model
{

/// <summary>
/// Information of a subscription to notifications to NRF events, included in subscription requests and responses
/// </summary>
class  SubscriptionData
{
public:
    SubscriptionData();
    virtual ~SubscriptionData() = default;


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

    bool operator==(const SubscriptionData& rhs) const;
    bool operator!=(const SubscriptionData& rhs) const;

    /////////////////////////////////////////////
    /// SubscriptionData members

    /// <summary>
    /// 
    /// </summary>
    std::string getNfStatusNotificationUri() const;
    void setNfStatusNotificationUri(std::string const& value);
    /// <summary>
    /// String uniquely identifying a NF instance. The format of the NF Instance ID shall be a Universally Unique Identifier (UUID) version 4, as described in IETF RFC 4122.
    /// </summary>
    std::string getReqNfInstanceId() const;
    void setReqNfInstanceId(std::string const& value);
    bool reqNfInstanceIdIsSet() const;
    void unsetReqNfInstanceId();
    /// <summary>
    /// 
    /// </summary>
    OneOfNfInstanceIdCondNfInstanceIdListCondNfTypeCondServiceNameCondServiceNameListCondAmfCondGuamiListCondNetworkSliceCondNfGroupCondNfGroupListCondNfSetCondNfServiceSetCondUpfCondScpDomainCondNwdafCondNefCondDccfCond getSubscrCond() const;
    void setSubscrCond(OneOfNfInstanceIdCondNfInstanceIdListCondNfTypeCondServiceNameCondServiceNameListCondAmfCondGuamiListCondNetworkSliceCondNfGroupCondNfGroupListCondNfSetCondNfServiceSetCondUpfCondScpDomainCondNwdafCondNefCondDccfCond const& value);
    bool subscrCondIsSet() const;
    void unsetSubscrCond();
    /// <summary>
    /// 
    /// </summary>
    std::string getSubscriptionId() const;
    void setSubscriptionId(std::string const& value);
    /// <summary>
    /// string with format \&quot;date-time\&quot; as defined in OpenAPI.
    /// </summary>
    std::string getValidityTime() const;
    void setValidityTime(std::string const& value);
    bool validityTimeIsSet() const;
    void unsetValidityTime();
    /// <summary>
    /// 
    /// </summary>
    std::vector<NotificationEventType> getReqNotifEvents() const;
    void setReqNotifEvents(std::vector<NotificationEventType> const& value);
    bool reqNotifEventsIsSet() const;
    void unsetReqNotifEvents();
    /// <summary>
    /// 
    /// </summary>
    PlmnId getPlmnId() const;
    void setPlmnId(PlmnId const& value);
    bool plmnIdIsSet() const;
    void unsetPlmnId();
    /// <summary>
    /// This represents the Network Identifier, which together with a PLMN ID is used to identify an SNPN (see 3GPP TS 23.003 and 3GPP TS 23.501 clause 5.30.2.1).
    /// </summary>
    std::string getNid() const;
    void setNid(std::string const& value);
    bool nidIsSet() const;
    void unsetNid();
    /// <summary>
    /// 
    /// </summary>
    NotifCondition getNotifCondition() const;
    void setNotifCondition(NotifCondition const& value);
    bool notifConditionIsSet() const;
    void unsetNotifCondition();
    /// <summary>
    /// 
    /// </summary>
    NFType getReqNfType() const;
    void setReqNfType(NFType const& value);
    bool reqNfTypeIsSet() const;
    void unsetReqNfType();
    /// <summary>
    /// Fully Qualified Domain Name
    /// </summary>
    std::string getReqNfFqdn() const;
    void setReqNfFqdn(std::string const& value);
    bool reqNfFqdnIsSet() const;
    void unsetReqNfFqdn();
    /// <summary>
    /// 
    /// </summary>
    std::vector<Snssai> getReqSnssais() const;
    void setReqSnssais(std::vector<Snssai> const& value);
    bool reqSnssaisIsSet() const;
    void unsetReqSnssais();
    /// <summary>
    /// 
    /// </summary>
    std::vector<PlmnSnssai> getReqPerPlmnSnssais() const;
    void setReqPerPlmnSnssais(std::vector<PlmnSnssai> const& value);
    bool reqPerPlmnSnssaisIsSet() const;
    void unsetReqPerPlmnSnssais();
    /// <summary>
    /// 
    /// </summary>
    std::vector<PlmnId> getReqPlmnList() const;
    void setReqPlmnList(std::vector<PlmnId> const& value);
    bool reqPlmnListIsSet() const;
    void unsetReqPlmnList();
    /// <summary>
    /// 
    /// </summary>
    std::vector<PlmnIdNid> getReqSnpnList() const;
    void setReqSnpnList(std::vector<PlmnIdNid> const& value);
    bool reqSnpnListIsSet() const;
    void unsetReqSnpnList();
    /// <summary>
    /// 
    /// </summary>
    std::vector<std::string> getServingScope() const;
    void setServingScope(std::vector<std::string> const& value);
    bool servingScopeIsSet() const;
    void unsetServingScope();
    /// <summary>
    /// 
    /// </summary>
    std::string getRequesterFeatures() const;
    void setRequesterFeatures(std::string const& value);
    bool requesterFeaturesIsSet() const;
    void unsetRequesterFeatures();
    /// <summary>
    /// 
    /// </summary>
    std::string getNrfSupportedFeatures() const;
    void setNrfSupportedFeatures(std::string const& value);
    bool nrfSupportedFeaturesIsSet() const;
    void unsetNrfSupportedFeatures();
    /// <summary>
    /// String providing an URI formatted according to RFC 3986
    /// </summary>
    std::string getHnrfUri() const;
    void setHnrfUri(std::string const& value);
    bool hnrfUriIsSet() const;
    void unsetHnrfUri();

    friend void to_json(nlohmann::json& j, const SubscriptionData& o);
    friend void from_json(const nlohmann::json& j, SubscriptionData& o);
protected:
    std::string m_NfStatusNotificationUri;

    std::string m_ReqNfInstanceId;
    bool m_ReqNfInstanceIdIsSet;
    OneOfNfInstanceIdCondNfInstanceIdListCondNfTypeCondServiceNameCondServiceNameListCondAmfCondGuamiListCondNetworkSliceCondNfGroupCondNfGroupListCondNfSetCondNfServiceSetCondUpfCondScpDomainCondNwdafCondNefCondDccfCond m_SubscrCond;
    bool m_SubscrCondIsSet;
    std::string m_SubscriptionId;

    std::string m_ValidityTime;
    bool m_ValidityTimeIsSet;
    std::vector<NotificationEventType> m_ReqNotifEvents;
    bool m_ReqNotifEventsIsSet;
    PlmnId m_PlmnId;
    bool m_PlmnIdIsSet;
    std::string m_Nid;
    bool m_NidIsSet;
    NotifCondition m_NotifCondition;
    bool m_NotifConditionIsSet;
    NFType m_ReqNfType;
    bool m_ReqNfTypeIsSet;
    std::string m_ReqNfFqdn;
    bool m_ReqNfFqdnIsSet;
    std::vector<Snssai> m_ReqSnssais;
    bool m_ReqSnssaisIsSet;
    std::vector<PlmnSnssai> m_ReqPerPlmnSnssais;
    bool m_ReqPerPlmnSnssaisIsSet;
    std::vector<PlmnId> m_ReqPlmnList;
    bool m_ReqPlmnListIsSet;
    std::vector<PlmnIdNid> m_ReqSnpnList;
    bool m_ReqSnpnListIsSet;
    std::vector<std::string> m_ServingScope;
    bool m_ServingScopeIsSet;
    std::string m_RequesterFeatures;
    bool m_RequesterFeaturesIsSet;
    std::string m_NrfSupportedFeatures;
    bool m_NrfSupportedFeaturesIsSet;
    std::string m_HnrfUri;
    bool m_HnrfUriIsSet;
    
};

} // namespace org::openapitools::server::model

#endif /* SubscriptionData_H_ */
