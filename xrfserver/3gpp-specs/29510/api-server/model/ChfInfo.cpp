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


#include "ChfInfo.h"
#include "Helpers.h"

#include <sstream>

namespace org::openapitools::server::model
{

ChfInfo::ChfInfo()
{
    m_SupiRangeListIsSet = false;
    m_GpsiRangeListIsSet = false;
    m_PlmnRangeListIsSet = false;
    m_GroupId = "";
    m_GroupIdIsSet = false;
    m_PrimaryChfInstance = "";
    m_PrimaryChfInstanceIsSet = false;
    m_SecondaryChfInstance = "";
    m_SecondaryChfInstanceIsSet = false;
    
}

void ChfInfo::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::openapitools::server::helpers::ValidationException(msg.str());
    }
}

bool ChfInfo::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool ChfInfo::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "ChfInfo" : pathPrefix;

         
    if (supiRangeListIsSet())
    {
        const std::vector<SupiRange>& value = m_SupiRangeList;
        const std::string currentValuePath = _pathPrefix + ".supiRangeList";
                
        
        if (value.size() < 1)
        {
            success = false;
            msg << currentValuePath << ": must have at least 1 elements;";
        }
        { // Recursive validation of array elements
            const std::string oldValuePath = currentValuePath;
            int i = 0;
            for (const SupiRange& value : value)
            { 
                const std::string currentValuePath = oldValuePath + "[" + std::to_string(i) + "]";
                        
        success = value.validate(msg, currentValuePath + ".supiRangeList") && success;
 
                i++;
            }
        }

    }
         
    if (gpsiRangeListIsSet())
    {
        const std::vector<IdentityRange>& value = m_GpsiRangeList;
        const std::string currentValuePath = _pathPrefix + ".gpsiRangeList";
                
        
        if (value.size() < 1)
        {
            success = false;
            msg << currentValuePath << ": must have at least 1 elements;";
        }
        { // Recursive validation of array elements
            const std::string oldValuePath = currentValuePath;
            int i = 0;
            for (const IdentityRange& value : value)
            { 
                const std::string currentValuePath = oldValuePath + "[" + std::to_string(i) + "]";
                        
        success = value.validate(msg, currentValuePath + ".gpsiRangeList") && success;
 
                i++;
            }
        }

    }
         
    if (plmnRangeListIsSet())
    {
        const std::vector<PlmnRange>& value = m_PlmnRangeList;
        const std::string currentValuePath = _pathPrefix + ".plmnRangeList";
                
        
        if (value.size() < 1)
        {
            success = false;
            msg << currentValuePath << ": must have at least 1 elements;";
        }
        { // Recursive validation of array elements
            const std::string oldValuePath = currentValuePath;
            int i = 0;
            for (const PlmnRange& value : value)
            { 
                const std::string currentValuePath = oldValuePath + "[" + std::to_string(i) + "]";
                        
        success = value.validate(msg, currentValuePath + ".plmnRangeList") && success;
 
                i++;
            }
        }

    }
                
    return success;
}

bool ChfInfo::operator==(const ChfInfo& rhs) const
{
    return
    
    
    
    ((!supiRangeListIsSet() && !rhs.supiRangeListIsSet()) || (supiRangeListIsSet() && rhs.supiRangeListIsSet() && getSupiRangeList() == rhs.getSupiRangeList())) &&
    
    
    ((!gpsiRangeListIsSet() && !rhs.gpsiRangeListIsSet()) || (gpsiRangeListIsSet() && rhs.gpsiRangeListIsSet() && getGpsiRangeList() == rhs.getGpsiRangeList())) &&
    
    
    ((!plmnRangeListIsSet() && !rhs.plmnRangeListIsSet()) || (plmnRangeListIsSet() && rhs.plmnRangeListIsSet() && getPlmnRangeList() == rhs.getPlmnRangeList())) &&
    
    
    ((!groupIdIsSet() && !rhs.groupIdIsSet()) || (groupIdIsSet() && rhs.groupIdIsSet() && getGroupId() == rhs.getGroupId())) &&
    
    
    ((!primaryChfInstanceIsSet() && !rhs.primaryChfInstanceIsSet()) || (primaryChfInstanceIsSet() && rhs.primaryChfInstanceIsSet() && getPrimaryChfInstance() == rhs.getPrimaryChfInstance())) &&
    
    
    ((!secondaryChfInstanceIsSet() && !rhs.secondaryChfInstanceIsSet()) || (secondaryChfInstanceIsSet() && rhs.secondaryChfInstanceIsSet() && getSecondaryChfInstance() == rhs.getSecondaryChfInstance()))
    
    ;
}

bool ChfInfo::operator!=(const ChfInfo& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const ChfInfo& o)
{
    j = nlohmann::json();
    if(o.supiRangeListIsSet() || !o.m_SupiRangeList.empty())
        j["supiRangeList"] = o.m_SupiRangeList;
    if(o.gpsiRangeListIsSet() || !o.m_GpsiRangeList.empty())
        j["gpsiRangeList"] = o.m_GpsiRangeList;
    if(o.plmnRangeListIsSet() || !o.m_PlmnRangeList.empty())
        j["plmnRangeList"] = o.m_PlmnRangeList;
    if(o.groupIdIsSet())
        j["groupId"] = o.m_GroupId;
    if(o.primaryChfInstanceIsSet())
        j["primaryChfInstance"] = o.m_PrimaryChfInstance;
    if(o.secondaryChfInstanceIsSet())
        j["secondaryChfInstance"] = o.m_SecondaryChfInstance;
    
}

void from_json(const nlohmann::json& j, ChfInfo& o)
{
    if(j.find("supiRangeList") != j.end())
    {
        j.at("supiRangeList").get_to(o.m_SupiRangeList);
        o.m_SupiRangeListIsSet = true;
    } 
    if(j.find("gpsiRangeList") != j.end())
    {
        j.at("gpsiRangeList").get_to(o.m_GpsiRangeList);
        o.m_GpsiRangeListIsSet = true;
    } 
    if(j.find("plmnRangeList") != j.end())
    {
        j.at("plmnRangeList").get_to(o.m_PlmnRangeList);
        o.m_PlmnRangeListIsSet = true;
    } 
    if(j.find("groupId") != j.end())
    {
        j.at("groupId").get_to(o.m_GroupId);
        o.m_GroupIdIsSet = true;
    } 
    if(j.find("primaryChfInstance") != j.end())
    {
        j.at("primaryChfInstance").get_to(o.m_PrimaryChfInstance);
        o.m_PrimaryChfInstanceIsSet = true;
    } 
    if(j.find("secondaryChfInstance") != j.end())
    {
        j.at("secondaryChfInstance").get_to(o.m_SecondaryChfInstance);
        o.m_SecondaryChfInstanceIsSet = true;
    } 
    
}

std::vector<SupiRange> ChfInfo::getSupiRangeList() const
{
    return m_SupiRangeList;
}
void ChfInfo::setSupiRangeList(std::vector<SupiRange> const& value)
{
    m_SupiRangeList = value;
    m_SupiRangeListIsSet = true;
}
bool ChfInfo::supiRangeListIsSet() const
{
    return m_SupiRangeListIsSet;
}
void ChfInfo::unsetSupiRangeList()
{
    m_SupiRangeListIsSet = false;
}
std::vector<IdentityRange> ChfInfo::getGpsiRangeList() const
{
    return m_GpsiRangeList;
}
void ChfInfo::setGpsiRangeList(std::vector<IdentityRange> const& value)
{
    m_GpsiRangeList = value;
    m_GpsiRangeListIsSet = true;
}
bool ChfInfo::gpsiRangeListIsSet() const
{
    return m_GpsiRangeListIsSet;
}
void ChfInfo::unsetGpsiRangeList()
{
    m_GpsiRangeListIsSet = false;
}
std::vector<PlmnRange> ChfInfo::getPlmnRangeList() const
{
    return m_PlmnRangeList;
}
void ChfInfo::setPlmnRangeList(std::vector<PlmnRange> const& value)
{
    m_PlmnRangeList = value;
    m_PlmnRangeListIsSet = true;
}
bool ChfInfo::plmnRangeListIsSet() const
{
    return m_PlmnRangeListIsSet;
}
void ChfInfo::unsetPlmnRangeList()
{
    m_PlmnRangeListIsSet = false;
}
std::string ChfInfo::getGroupId() const
{
    return m_GroupId;
}
void ChfInfo::setGroupId(std::string const& value)
{
    m_GroupId = value;
    m_GroupIdIsSet = true;
}
bool ChfInfo::groupIdIsSet() const
{
    return m_GroupIdIsSet;
}
void ChfInfo::unsetGroupId()
{
    m_GroupIdIsSet = false;
}
std::string ChfInfo::getPrimaryChfInstance() const
{
    return m_PrimaryChfInstance;
}
void ChfInfo::setPrimaryChfInstance(std::string const& value)
{
    m_PrimaryChfInstance = value;
    m_PrimaryChfInstanceIsSet = true;
}
bool ChfInfo::primaryChfInstanceIsSet() const
{
    return m_PrimaryChfInstanceIsSet;
}
void ChfInfo::unsetPrimaryChfInstance()
{
    m_PrimaryChfInstanceIsSet = false;
}
std::string ChfInfo::getSecondaryChfInstance() const
{
    return m_SecondaryChfInstance;
}
void ChfInfo::setSecondaryChfInstance(std::string const& value)
{
    m_SecondaryChfInstance = value;
    m_SecondaryChfInstanceIsSet = true;
}
bool ChfInfo::secondaryChfInstanceIsSet() const
{
    return m_SecondaryChfInstanceIsSet;
}
void ChfInfo::unsetSecondaryChfInstance()
{
    m_SecondaryChfInstanceIsSet = false;
}


} // namespace org::openapitools::server::model

