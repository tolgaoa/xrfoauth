/**
* XRF OAuth2 Initial Authentication Request API
* XRF OAuth2 Authorization server, initial authentication with the xApp API 
*
* The version of the OpenAPI document: 1
* Contact: tolgaoa@vt.edu
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/


#include "InitAuthClaims.h"
#include "Helpers.h"

#include <sstream>

namespace xrf::model
{

InitAuthClaims::InitAuthClaims()
{
    m_RootCA = "";
    m_Pubkey = "";
    m_Identity = "";
    
}

void InitAuthClaims::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw xrf::helpers::ValidationException(msg.str());
    }
}

bool InitAuthClaims::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool InitAuthClaims::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "InitAuthClaims" : pathPrefix;

                
    return success;
}

bool InitAuthClaims::operator==(const InitAuthClaims& rhs) const
{
    return
    
    
    (getRootCA() == rhs.getRootCA())
     &&
    
    (getPubkey() == rhs.getPubkey())
     &&
    
    (getIdentity() == rhs.getIdentity())
    
    
    ;
}

bool InitAuthClaims::operator!=(const InitAuthClaims& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const InitAuthClaims& o)
{
    j = nlohmann::json();
    j["rootCA"] = o.m_RootCA;
    j["pubkey"] = o.m_Pubkey;
    j["identity"] = o.m_Identity;
    
}

void from_json(const nlohmann::json& j, InitAuthClaims& o)
{
    j.at("rootCA").get_to(o.m_RootCA);
    j.at("pubkey").get_to(o.m_Pubkey);
    j.at("identity").get_to(o.m_Identity);
    
}

std::string InitAuthClaims::getRootCA() const
{
    return m_RootCA;
}
void InitAuthClaims::setRootCA(std::string const& value)
{
    m_RootCA = value;
}
std::string InitAuthClaims::getPubkey() const
{
    return m_Pubkey;
}
void InitAuthClaims::setPubkey(std::string const& value)
{
    m_Pubkey = value;
}
std::string InitAuthClaims::getIdentity() const
{
    return m_Identity;
}
void InitAuthClaims::setIdentity(std::string const& value)
{
    m_Identity = value;
}


} // namespace xrf::model

