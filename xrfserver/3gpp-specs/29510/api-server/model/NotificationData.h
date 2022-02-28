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
 * NotificationData.h
 *
 * Data sent in notifications from NRF to subscribed NF Instances
 */

#ifndef NotificationData_H_
#define NotificationData_H_


#include "NFProfile.h"
#include "ChangeItem.h"
#include "ConditionEventType.h"
#include <string>
#include "NotificationEventType.h"
#include <vector>
#include <nlohmann/json.hpp>

namespace org::openapitools::server::model
{

/// <summary>
/// Data sent in notifications from NRF to subscribed NF Instances
/// </summary>
class  NotificationData
{
public:
    NotificationData();
    virtual ~NotificationData() = default;


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

    bool operator==(const NotificationData& rhs) const;
    bool operator!=(const NotificationData& rhs) const;

    /////////////////////////////////////////////
    /// NotificationData members

    /// <summary>
    /// 
    /// </summary>
    NotificationEventType getEvent() const;
    void setEvent(NotificationEventType const& value);
    /// <summary>
    /// String providing an URI formatted according to RFC 3986
    /// </summary>
    std::string getNfInstanceUri() const;
    void setNfInstanceUri(std::string const& value);
    /// <summary>
    /// 
    /// </summary>
    NFProfile getNfProfile() const;
    void setNfProfile(NFProfile const& value);
    bool nfProfileIsSet() const;
    void unsetNfProfile();
    /// <summary>
    /// 
    /// </summary>
    std::vector<ChangeItem> getProfileChanges() const;
    void setProfileChanges(std::vector<ChangeItem> const& value);
    bool profileChangesIsSet() const;
    void unsetProfileChanges();
    /// <summary>
    /// 
    /// </summary>
    ConditionEventType getConditionEvent() const;
    void setConditionEvent(ConditionEventType const& value);
    bool conditionEventIsSet() const;
    void unsetConditionEvent();

    friend void to_json(nlohmann::json& j, const NotificationData& o);
    friend void from_json(const nlohmann::json& j, NotificationData& o);
protected:
    NotificationEventType m_Event;

    std::string m_NfInstanceUri;

    NFProfile m_NfProfile;
    bool m_NfProfileIsSet;
    std::vector<ChangeItem> m_ProfileChanges;
    bool m_ProfileChangesIsSet;
    ConditionEventType m_ConditionEvent;
    bool m_ConditionEventIsSet;
    
};

} // namespace org::openapitools::server::model

#endif /* NotificationData_H_ */
