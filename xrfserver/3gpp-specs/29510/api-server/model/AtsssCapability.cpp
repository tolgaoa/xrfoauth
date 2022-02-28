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


#include "AtsssCapability.h"
#include "Helpers.h"

#include <sstream>

namespace org::openapitools::server::model
{

AtsssCapability::AtsssCapability()
{
    m_AtsssLL = false;
    m_AtsssLLIsSet = false;
    m_Mptcp = false;
    m_MptcpIsSet = false;
    m_RttWithoutPmf = false;
    m_RttWithoutPmfIsSet = false;
    
}

void AtsssCapability::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::openapitools::server::helpers::ValidationException(msg.str());
    }
}

bool AtsssCapability::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool AtsssCapability::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "AtsssCapability" : pathPrefix;

                
    return success;
}

bool AtsssCapability::operator==(const AtsssCapability& rhs) const
{
    return
    
    
    
    ((!atsssLLIsSet() && !rhs.atsssLLIsSet()) || (atsssLLIsSet() && rhs.atsssLLIsSet() && isAtsssLL() == rhs.isAtsssLL())) &&
    
    
    ((!mptcpIsSet() && !rhs.mptcpIsSet()) || (mptcpIsSet() && rhs.mptcpIsSet() && isMptcp() == rhs.isMptcp())) &&
    
    
    ((!rttWithoutPmfIsSet() && !rhs.rttWithoutPmfIsSet()) || (rttWithoutPmfIsSet() && rhs.rttWithoutPmfIsSet() && isRttWithoutPmf() == rhs.isRttWithoutPmf()))
    
    ;
}

bool AtsssCapability::operator!=(const AtsssCapability& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const AtsssCapability& o)
{
    j = nlohmann::json();
    if(o.atsssLLIsSet())
        j["atsssLL"] = o.m_AtsssLL;
    if(o.mptcpIsSet())
        j["mptcp"] = o.m_Mptcp;
    if(o.rttWithoutPmfIsSet())
        j["rttWithoutPmf"] = o.m_RttWithoutPmf;
    
}

void from_json(const nlohmann::json& j, AtsssCapability& o)
{
    if(j.find("atsssLL") != j.end())
    {
        j.at("atsssLL").get_to(o.m_AtsssLL);
        o.m_AtsssLLIsSet = true;
    } 
    if(j.find("mptcp") != j.end())
    {
        j.at("mptcp").get_to(o.m_Mptcp);
        o.m_MptcpIsSet = true;
    } 
    if(j.find("rttWithoutPmf") != j.end())
    {
        j.at("rttWithoutPmf").get_to(o.m_RttWithoutPmf);
        o.m_RttWithoutPmfIsSet = true;
    } 
    
}

bool AtsssCapability::isAtsssLL() const
{
    return m_AtsssLL;
}
void AtsssCapability::setAtsssLL(bool const value)
{
    m_AtsssLL = value;
    m_AtsssLLIsSet = true;
}
bool AtsssCapability::atsssLLIsSet() const
{
    return m_AtsssLLIsSet;
}
void AtsssCapability::unsetAtsssLL()
{
    m_AtsssLLIsSet = false;
}
bool AtsssCapability::isMptcp() const
{
    return m_Mptcp;
}
void AtsssCapability::setMptcp(bool const value)
{
    m_Mptcp = value;
    m_MptcpIsSet = true;
}
bool AtsssCapability::mptcpIsSet() const
{
    return m_MptcpIsSet;
}
void AtsssCapability::unsetMptcp()
{
    m_MptcpIsSet = false;
}
bool AtsssCapability::isRttWithoutPmf() const
{
    return m_RttWithoutPmf;
}
void AtsssCapability::setRttWithoutPmf(bool const value)
{
    m_RttWithoutPmf = value;
    m_RttWithoutPmfIsSet = true;
}
bool AtsssCapability::rttWithoutPmfIsSet() const
{
    return m_RttWithoutPmfIsSet;
}
void AtsssCapability::unsetRttWithoutPmf()
{
    m_RttWithoutPmfIsSet = false;
}


} // namespace org::openapitools::server::model

