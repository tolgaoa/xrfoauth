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


#include "MbsServiceArea.h"
#include "Helpers.h"

#include <sstream>

namespace org::openapitools::server::model
{

MbsServiceArea::MbsServiceArea()
{
    m_NcgiListIsSet = false;
    m_TaiListIsSet = false;
    
}

void MbsServiceArea::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::openapitools::server::helpers::ValidationException(msg.str());
    }
}

bool MbsServiceArea::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool MbsServiceArea::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "MbsServiceArea" : pathPrefix;

         
    if (ncgiListIsSet())
    {
        const std::vector<NcgiTai>& value = m_NcgiList;
        const std::string currentValuePath = _pathPrefix + ".ncgiList";
                
        
        if (value.size() < 1)
        {
            success = false;
            msg << currentValuePath << ": must have at least 1 elements;";
        }
        { // Recursive validation of array elements
            const std::string oldValuePath = currentValuePath;
            int i = 0;
            for (const NcgiTai& value : value)
            { 
                const std::string currentValuePath = oldValuePath + "[" + std::to_string(i) + "]";
                        
        success = value.validate(msg, currentValuePath + ".ncgiList") && success;
 
                i++;
            }
        }

    }
         
    if (taiListIsSet())
    {
        const std::vector<Tai>& value = m_TaiList;
        const std::string currentValuePath = _pathPrefix + ".taiList";
                
        
        if (value.size() < 1)
        {
            success = false;
            msg << currentValuePath << ": must have at least 1 elements;";
        }
        { // Recursive validation of array elements
            const std::string oldValuePath = currentValuePath;
            int i = 0;
            for (const Tai& value : value)
            { 
                const std::string currentValuePath = oldValuePath + "[" + std::to_string(i) + "]";
                        
        success = value.validate(msg, currentValuePath + ".taiList") && success;
 
                i++;
            }
        }

    }
    
    return success;
}

bool MbsServiceArea::operator==(const MbsServiceArea& rhs) const
{
    return
    
    
    
    ((!ncgiListIsSet() && !rhs.ncgiListIsSet()) || (ncgiListIsSet() && rhs.ncgiListIsSet() && getNcgiList() == rhs.getNcgiList())) &&
    
    
    ((!taiListIsSet() && !rhs.taiListIsSet()) || (taiListIsSet() && rhs.taiListIsSet() && getTaiList() == rhs.getTaiList()))
    
    ;
}

bool MbsServiceArea::operator!=(const MbsServiceArea& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const MbsServiceArea& o)
{
    j = nlohmann::json();
    if(o.ncgiListIsSet() || !o.m_NcgiList.empty())
        j["ncgiList"] = o.m_NcgiList;
    if(o.taiListIsSet() || !o.m_TaiList.empty())
        j["taiList"] = o.m_TaiList;
    
}

void from_json(const nlohmann::json& j, MbsServiceArea& o)
{
    if(j.find("ncgiList") != j.end())
    {
        j.at("ncgiList").get_to(o.m_NcgiList);
        o.m_NcgiListIsSet = true;
    } 
    if(j.find("taiList") != j.end())
    {
        j.at("taiList").get_to(o.m_TaiList);
        o.m_TaiListIsSet = true;
    } 
    
}

std::vector<NcgiTai> MbsServiceArea::getNcgiList() const
{
    return m_NcgiList;
}
void MbsServiceArea::setNcgiList(std::vector<NcgiTai> const& value)
{
    m_NcgiList = value;
    m_NcgiListIsSet = true;
}
bool MbsServiceArea::ncgiListIsSet() const
{
    return m_NcgiListIsSet;
}
void MbsServiceArea::unsetNcgiList()
{
    m_NcgiListIsSet = false;
}
std::vector<Tai> MbsServiceArea::getTaiList() const
{
    return m_TaiList;
}
void MbsServiceArea::setTaiList(std::vector<Tai> const& value)
{
    m_TaiList = value;
    m_TaiListIsSet = true;
}
bool MbsServiceArea::taiListIsSet() const
{
    return m_TaiListIsSet;
}
void MbsServiceArea::unsetTaiList()
{
    m_TaiListIsSet = false;
}


} // namespace org::openapitools::server::model
