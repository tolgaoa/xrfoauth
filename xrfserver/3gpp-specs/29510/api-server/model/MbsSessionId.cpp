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


#include "MbsSessionId.h"
#include "Helpers.h"

#include <sstream>

namespace org::openapitools::server::model
{

MbsSessionId::MbsSessionId()
{
    m_TmgiIsSet = false;
    m_SsmIsSet = false;
    m_Nid = "";
    m_NidIsSet = false;
    
}

void MbsSessionId::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::openapitools::server::helpers::ValidationException(msg.str());
    }
}

bool MbsSessionId::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool MbsSessionId::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "MbsSessionId" : pathPrefix;

                 
    if (nidIsSet())
    {
        const std::string& value = m_Nid;
        const std::string currentValuePath = _pathPrefix + ".nid";
                
        

    }
    
    return success;
}

bool MbsSessionId::operator==(const MbsSessionId& rhs) const
{
    return
    
    
    
    ((!tmgiIsSet() && !rhs.tmgiIsSet()) || (tmgiIsSet() && rhs.tmgiIsSet() && getTmgi() == rhs.getTmgi())) &&
    
    
    ((!ssmIsSet() && !rhs.ssmIsSet()) || (ssmIsSet() && rhs.ssmIsSet() && getSsm() == rhs.getSsm())) &&
    
    
    ((!nidIsSet() && !rhs.nidIsSet()) || (nidIsSet() && rhs.nidIsSet() && getNid() == rhs.getNid()))
    
    ;
}

bool MbsSessionId::operator!=(const MbsSessionId& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const MbsSessionId& o)
{
    j = nlohmann::json();
    if(o.tmgiIsSet())
        j["tmgi"] = o.m_Tmgi;
    if(o.ssmIsSet())
        j["ssm"] = o.m_Ssm;
    if(o.nidIsSet())
        j["nid"] = o.m_Nid;
    
}

void from_json(const nlohmann::json& j, MbsSessionId& o)
{
    if(j.find("tmgi") != j.end())
    {
        j.at("tmgi").get_to(o.m_Tmgi);
        o.m_TmgiIsSet = true;
    } 
    if(j.find("ssm") != j.end())
    {
        j.at("ssm").get_to(o.m_Ssm);
        o.m_SsmIsSet = true;
    } 
    if(j.find("nid") != j.end())
    {
        j.at("nid").get_to(o.m_Nid);
        o.m_NidIsSet = true;
    } 
    
}

Tmgi MbsSessionId::getTmgi() const
{
    return m_Tmgi;
}
void MbsSessionId::setTmgi(Tmgi const& value)
{
    m_Tmgi = value;
    m_TmgiIsSet = true;
}
bool MbsSessionId::tmgiIsSet() const
{
    return m_TmgiIsSet;
}
void MbsSessionId::unsetTmgi()
{
    m_TmgiIsSet = false;
}
Ssm MbsSessionId::getSsm() const
{
    return m_Ssm;
}
void MbsSessionId::setSsm(Ssm const& value)
{
    m_Ssm = value;
    m_SsmIsSet = true;
}
bool MbsSessionId::ssmIsSet() const
{
    return m_SsmIsSet;
}
void MbsSessionId::unsetSsm()
{
    m_SsmIsSet = false;
}
std::string MbsSessionId::getNid() const
{
    return m_Nid;
}
void MbsSessionId::setNid(std::string const& value)
{
    m_Nid = value;
    m_NidIsSet = true;
}
bool MbsSessionId::nidIsSet() const
{
    return m_NidIsSet;
}
void MbsSessionId::unsetNid()
{
    m_NidIsSet = false;
}


} // namespace org::openapitools::server::model

