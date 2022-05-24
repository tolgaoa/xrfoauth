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


#include "SnssaiInfoItem.h"
#include "Helpers.h"

#include <sstream>

namespace org::openapitools::server::model
{

SnssaiInfoItem::SnssaiInfoItem()
{
    
}

void SnssaiInfoItem::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::openapitools::server::helpers::ValidationException(msg.str());
    }
}

bool SnssaiInfoItem::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool SnssaiInfoItem::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "SnssaiInfoItem" : pathPrefix;

             
    
    /* DnnInfoList */ {
        const std::vector<DnnInfoItem>& value = m_DnnInfoList;
        const std::string currentValuePath = _pathPrefix + ".dnnInfoList";
                
        
        if (value.size() < 1)
        {
            success = false;
            msg << currentValuePath << ": must have at least 1 elements;";
        }
        { // Recursive validation of array elements
            const std::string oldValuePath = currentValuePath;
            int i = 0;
            for (const DnnInfoItem& value : value)
            { 
                const std::string currentValuePath = oldValuePath + "[" + std::to_string(i) + "]";
                        
        success = value.validate(msg, currentValuePath + ".dnnInfoList") && success;
 
                i++;
            }
        }

    }
    
    return success;
}

bool SnssaiInfoItem::operator==(const SnssaiInfoItem& rhs) const
{
    return
    
    
    (getSNssai() == rhs.getSNssai())
     &&
    
    (getDnnInfoList() == rhs.getDnnInfoList())
    
    
    ;
}

bool SnssaiInfoItem::operator!=(const SnssaiInfoItem& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const SnssaiInfoItem& o)
{
    j = nlohmann::json();
    j["sNssai"] = o.m_SNssai;
    j["dnnInfoList"] = o.m_DnnInfoList;
    
}

void from_json(const nlohmann::json& j, SnssaiInfoItem& o)
{
    j.at("sNssai").get_to(o.m_SNssai);
    j.at("dnnInfoList").get_to(o.m_DnnInfoList);
    
}

ExtSnssai SnssaiInfoItem::getSNssai() const
{
    return m_SNssai;
}
void SnssaiInfoItem::setSNssai(ExtSnssai const& value)
{
    m_SNssai = value;
}
std::vector<DnnInfoItem> SnssaiInfoItem::getDnnInfoList() const
{
    return m_DnnInfoList;
}
void SnssaiInfoItem::setDnnInfoList(std::vector<DnnInfoItem> const& value)
{
    m_DnnInfoList = value;
}


} // namespace org::openapitools::server::model
