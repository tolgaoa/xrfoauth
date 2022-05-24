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


#include "5GDdnmfInfo.h"
#include "Helpers.h"

#include <sstream>

namespace org::openapitools::server::model
{

5GDdnmfInfo::5GDdnmfInfo()
{
    
}

void 5GDdnmfInfo::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::openapitools::server::helpers::ValidationException(msg.str());
    }
}

bool 5GDdnmfInfo::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool 5GDdnmfInfo::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "5GDdnmfInfo" : pathPrefix;

        
    return success;
}

bool 5GDdnmfInfo::operator==(const 5GDdnmfInfo& rhs) const
{
    return
    
    
    (getPlmnId() == rhs.getPlmnId())
    
    
    ;
}

bool 5GDdnmfInfo::operator!=(const 5GDdnmfInfo& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const 5GDdnmfInfo& o)
{
    j = nlohmann::json();
    j["plmnId"] = o.m_PlmnId;
    
}

void from_json(const nlohmann::json& j, 5GDdnmfInfo& o)
{
    j.at("plmnId").get_to(o.m_PlmnId);
    
}

PlmnId 5GDdnmfInfo::getPlmnId() const
{
    return m_PlmnId;
}
void 5GDdnmfInfo::setPlmnId(PlmnId const& value)
{
    m_PlmnId = value;
}


} // namespace org::openapitools::server::model
