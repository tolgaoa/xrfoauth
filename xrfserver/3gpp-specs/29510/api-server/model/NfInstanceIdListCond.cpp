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


#include "NfInstanceIdListCond.h"
#include "Helpers.h"

#include <sstream>

namespace org::openapitools::server::model
{

NfInstanceIdListCond::NfInstanceIdListCond()
{
    
}

void NfInstanceIdListCond::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::openapitools::server::helpers::ValidationException(msg.str());
    }
}

bool NfInstanceIdListCond::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool NfInstanceIdListCond::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "NfInstanceIdListCond" : pathPrefix;

         
    
    /* NfInstanceIdList */ {
        const std::vector<std::string>& value = m_NfInstanceIdList;
        const std::string currentValuePath = _pathPrefix + ".nfInstanceIdList";
                
        
        if (value.size() < 1)
        {
            success = false;
            msg << currentValuePath << ": must have at least 1 elements;";
        }
        { // Recursive validation of array elements
            const std::string oldValuePath = currentValuePath;
            int i = 0;
            for (const std::string& value : value)
            { 
                const std::string currentValuePath = oldValuePath + "[" + std::to_string(i) + "]";
                        
        
 
                i++;
            }
        }

    }
    
    return success;
}

bool NfInstanceIdListCond::operator==(const NfInstanceIdListCond& rhs) const
{
    return
    
    
    (getNfInstanceIdList() == rhs.getNfInstanceIdList())
    
    
    ;
}

bool NfInstanceIdListCond::operator!=(const NfInstanceIdListCond& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const NfInstanceIdListCond& o)
{
    j = nlohmann::json();
    j["nfInstanceIdList"] = o.m_NfInstanceIdList;
    
}

void from_json(const nlohmann::json& j, NfInstanceIdListCond& o)
{
    j.at("nfInstanceIdList").get_to(o.m_NfInstanceIdList);
    
}

std::vector<std::string> NfInstanceIdListCond::getNfInstanceIdList() const
{
    return m_NfInstanceIdList;
}
void NfInstanceIdListCond::setNfInstanceIdList(std::vector<std::string> const& value)
{
    m_NfInstanceIdList = value;
}


} // namespace org::openapitools::server::model

