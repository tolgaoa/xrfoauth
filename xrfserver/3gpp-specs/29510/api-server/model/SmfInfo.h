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
 * SmfInfo.h
 *
 * Information of an SMF NF Instance
 */

#ifndef SmfInfo_H_
#define SmfInfo_H_


#include "IpAddr.h"
#include "Tai.h"
#include <string>
#include "SnssaiSmfInfoItem.h"
#include "TaiRange.h"
#include <vector>
#include "AccessType.h"
#include <nlohmann/json.hpp>

namespace org::openapitools::server::model
{

/// <summary>
/// Information of an SMF NF Instance
/// </summary>
class  SmfInfo
{
public:
    SmfInfo();
    virtual ~SmfInfo() = default;


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

    bool operator==(const SmfInfo& rhs) const;
    bool operator!=(const SmfInfo& rhs) const;

    /////////////////////////////////////////////
    /// SmfInfo members

    /// <summary>
    /// 
    /// </summary>
    std::vector<SnssaiSmfInfoItem> getSNssaiSmfInfoList() const;
    void setSNssaiSmfInfoList(std::vector<SnssaiSmfInfoItem> const& value);
    /// <summary>
    /// 
    /// </summary>
    std::vector<Tai> getTaiList() const;
    void setTaiList(std::vector<Tai> const& value);
    bool taiListIsSet() const;
    void unsetTaiList();
    /// <summary>
    /// 
    /// </summary>
    std::vector<TaiRange> getTaiRangeList() const;
    void setTaiRangeList(std::vector<TaiRange> const& value);
    bool taiRangeListIsSet() const;
    void unsetTaiRangeList();
    /// <summary>
    /// Fully Qualified Domain Name
    /// </summary>
    std::string getPgwFqdn() const;
    void setPgwFqdn(std::string const& value);
    bool pgwFqdnIsSet() const;
    void unsetPgwFqdn();
    /// <summary>
    /// 
    /// </summary>
    std::vector<IpAddr> getPgwIpAddrList() const;
    void setPgwIpAddrList(std::vector<IpAddr> const& value);
    bool pgwIpAddrListIsSet() const;
    void unsetPgwIpAddrList();
    /// <summary>
    /// 
    /// </summary>
    std::vector<AccessType> getAccessType() const;
    void setAccessType(std::vector<AccessType> const& value);
    bool accessTypeIsSet() const;
    void unsetAccessType();
    /// <summary>
    /// 
    /// </summary>
    int32_t getPriority() const;
    void setPriority(int32_t const value);
    bool priorityIsSet() const;
    void unsetPriority();
    /// <summary>
    /// 
    /// </summary>
    bool isVsmfSupportInd() const;
    void setVsmfSupportInd(bool const value);
    bool vsmfSupportIndIsSet() const;
    void unsetVsmfSupportInd();
    /// <summary>
    /// 
    /// </summary>
    std::vector<std::string> getPgwFqdnList() const;
    void setPgwFqdnList(std::vector<std::string> const& value);
    bool pgwFqdnListIsSet() const;
    void unsetPgwFqdnList();

    friend void to_json(nlohmann::json& j, const SmfInfo& o);
    friend void from_json(const nlohmann::json& j, SmfInfo& o);
protected:
    std::vector<SnssaiSmfInfoItem> m_SNssaiSmfInfoList;

    std::vector<Tai> m_TaiList;
    bool m_TaiListIsSet;
    std::vector<TaiRange> m_TaiRangeList;
    bool m_TaiRangeListIsSet;
    std::string m_PgwFqdn;
    bool m_PgwFqdnIsSet;
    std::vector<IpAddr> m_PgwIpAddrList;
    bool m_PgwIpAddrListIsSet;
    std::vector<AccessType> m_AccessType;
    bool m_AccessTypeIsSet;
    int32_t m_Priority;
    bool m_PriorityIsSet;
    bool m_VsmfSupportInd;
    bool m_VsmfSupportIndIsSet;
    std::vector<std::string> m_PgwFqdnList;
    bool m_PgwFqdnListIsSet;
    
};

} // namespace org::openapitools::server::model

#endif /* SmfInfo_H_ */
