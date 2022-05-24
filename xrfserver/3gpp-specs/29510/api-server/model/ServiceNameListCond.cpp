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


#include "ServiceNameListCond.h"
#include "Helpers.h"

#include <sstream>

namespace org::openapitools::server::model
{

ServiceNameListCond::ServiceNameListCond()
{
    m_ConditionType = "";
    
}

void ServiceNameListCond::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::openapitools::server::helpers::ValidationException(msg.str());
    }
}

bool ServiceNameListCond::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool ServiceNameListCond::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "ServiceNameListCond" : pathPrefix;

             
    
    /* ServiceNameList */ {
        const std::vector<ServiceName>& value = m_ServiceNameList;
        const std::string currentValuePath = _pathPrefix + ".serviceNameList";
                
        
        if (value.size() < 1)
        {
            success = false;
            msg << currentValuePath << ": must have at least 1 elements;";
        }
        { // Recursive validation of array elements
            const std::string oldValuePath = currentValuePath;
            int i = 0;
            for (const ServiceName& value : value)
            { 
                const std::string currentValuePath = oldValuePath + "[" + std::to_string(i) + "]";
                        
        success = value.validate(msg, currentValuePath + ".serviceNameList") && success;
 
                i++;
            }
        }

    }
    
    return success;
}

bool ServiceNameListCond::operator==(const ServiceNameListCond& rhs) const
{
    return
    
    
    (getConditionType() == rhs.getConditionType())
     &&
    
    (getServiceNameList() == rhs.getServiceNameList())
    
    
    ;
}

bool ServiceNameListCond::operator!=(const ServiceNameListCond& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const ServiceNameListCond& o)
{
    j = nlohmann::json();
    j["conditionType"] = o.m_ConditionType;
    j["serviceNameList"] = o.m_ServiceNameList;
    
}

void from_json(const nlohmann::json& j, ServiceNameListCond& o)
{
    j.at("conditionType").get_to(o.m_ConditionType);
    j.at("serviceNameList").get_to(o.m_ServiceNameList);
    
}

std::string ServiceNameListCond::getConditionType() const
{
    return m_ConditionType;
}
void ServiceNameListCond::setConditionType(std::string const& value)
{
    m_ConditionType = value;
}
std::vector<ServiceName> ServiceNameListCond::getServiceNameList() const
{
    return m_ServiceNameList;
}
void ServiceNameListCond::setServiceNameList(std::vector<ServiceName> const& value)
{
    m_ServiceNameList = value;
}


} // namespace org::openapitools::server::model
