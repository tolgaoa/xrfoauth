/**
* NRF Bootstrapping
* NRF Bootstrapping. © 2021, 3GPP Organizational Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved. 
*
* The version of the OpenAPI document: 1.1.0-alpha.3
* 
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/


#include "BootstrappingInfo.h"
#include "Helpers.h"

#include <sstream>

namespace org::openapitools::server::model
{

BootstrappingInfo::BootstrappingInfo()
{
    m_StatusIsSet = false;
    m_NrfFeaturesIsSet = false;
    m_Oauth2RequiredIsSet = false;
    
}

void BootstrappingInfo::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::openapitools::server::helpers::ValidationException(msg.str());
    }
}

bool BootstrappingInfo::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool BootstrappingInfo::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "BootstrappingInfo" : pathPrefix;

             
    
    /* _links */ {
        const std::map<std::string, LinksValueSchema>& value = m__links;
        const std::string currentValuePath = _pathPrefix + ".links";
                
        

    }
         
    if (nrfFeaturesIsSet())
    {
        const std::map<std::string, std::string>& value = m_NrfFeatures;
        const std::string currentValuePath = _pathPrefix + ".nrfFeatures";
                
        

    }
         
    if (oauth2RequiredIsSet())
    {
        const std::map<std::string, bool>& value = m_Oauth2Required;
        const std::string currentValuePath = _pathPrefix + ".oauth2Required";
                
        

    }
    
    return success;
}

bool BootstrappingInfo::operator==(const BootstrappingInfo& rhs) const
{
    return
    
    
    
    ((!statusIsSet() && !rhs.statusIsSet()) || (statusIsSet() && rhs.statusIsSet() && getStatus() == rhs.getStatus())) &&
    
    (getLinks() == rhs.getLinks())
     &&
    
    
    ((!nrfFeaturesIsSet() && !rhs.nrfFeaturesIsSet()) || (nrfFeaturesIsSet() && rhs.nrfFeaturesIsSet() && getNrfFeatures() == rhs.getNrfFeatures())) &&
    
    
    ((!oauth2RequiredIsSet() && !rhs.oauth2RequiredIsSet()) || (oauth2RequiredIsSet() && rhs.oauth2RequiredIsSet() && getOauth2Required() == rhs.getOauth2Required()))
    
    ;
}

bool BootstrappingInfo::operator!=(const BootstrappingInfo& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const BootstrappingInfo& o)
{
    j = nlohmann::json();
    if(o.statusIsSet())
        j["status"] = o.m_Status;
    j["_links"] = o.m__links;
    if(o.nrfFeaturesIsSet() || !o.m_NrfFeatures.empty())
        j["nrfFeatures"] = o.m_NrfFeatures;
    if(o.oauth2RequiredIsSet() || !o.m_Oauth2Required.empty())
        j["oauth2Required"] = o.m_Oauth2Required;
    
}

void from_json(const nlohmann::json& j, BootstrappingInfo& o)
{
    if(j.find("status") != j.end())
    {
        j.at("status").get_to(o.m_Status);
        o.m_StatusIsSet = true;
    } 
    j.at("_links").get_to(o.m__links);
    if(j.find("nrfFeatures") != j.end())
    {
        j.at("nrfFeatures").get_to(o.m_NrfFeatures);
        o.m_NrfFeaturesIsSet = true;
    } 
    if(j.find("oauth2Required") != j.end())
    {
        j.at("oauth2Required").get_to(o.m_Oauth2Required);
        o.m_Oauth2RequiredIsSet = true;
    } 
    
}

Status BootstrappingInfo::getStatus() const
{
    return m_Status;
}
void BootstrappingInfo::setStatus(Status const& value)
{
    m_Status = value;
    m_StatusIsSet = true;
}
bool BootstrappingInfo::statusIsSet() const
{
    return m_StatusIsSet;
}
void BootstrappingInfo::unsetStatus()
{
    m_StatusIsSet = false;
}
std::map<std::string, LinksValueSchema> BootstrappingInfo::getLinks() const
{
    return m__links;
}
void BootstrappingInfo::setLinks(std::map<std::string, LinksValueSchema> const& value)
{
    m__links = value;
}
std::map<std::string, std::string> BootstrappingInfo::getNrfFeatures() const
{
    return m_NrfFeatures;
}
void BootstrappingInfo::setNrfFeatures(std::map<std::string, std::string> const& value)
{
    m_NrfFeatures = value;
    m_NrfFeaturesIsSet = true;
}
bool BootstrappingInfo::nrfFeaturesIsSet() const
{
    return m_NrfFeaturesIsSet;
}
void BootstrappingInfo::unsetNrfFeatures()
{
    m_NrfFeaturesIsSet = false;
}
std::map<std::string, bool> BootstrappingInfo::getOauth2Required() const
{
    return m_Oauth2Required;
}
void BootstrappingInfo::setOauth2Required(std::map<std::string, bool> const value)
{
    m_Oauth2Required = value;
    m_Oauth2RequiredIsSet = true;
}
bool BootstrappingInfo::oauth2RequiredIsSet() const
{
    return m_Oauth2RequiredIsSet;
}
void BootstrappingInfo::unsetOauth2Required()
{
    m_Oauth2RequiredIsSet = false;
}


} // namespace org::openapitools::server::model

