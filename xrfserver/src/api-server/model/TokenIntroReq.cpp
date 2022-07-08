/**
* XRF OAuth2 Token Introspection Request API
* XRF OAuth2 Authorization server, token introspection API 
*
* The version of the OpenAPI document: 1
* Contact: tolgaoa@vt.edu
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/


#include "TokenIntroReq.h"
#include "Helpers.h"

#include <sstream>

namespace xrf::model
{

TokenIntroReq::TokenIntroReq()
{
    m_AccessToken = "";
    m_XappInstanceId = "";
    m_TargetxAppId = "";
    m_HxrfTokenIntroUri = "";
    m_HxrfTokenIntroUriIsSet = false;
    
}

void TokenIntroReq::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw xrf::helpers::ValidationException(msg.str());
    }
}

bool TokenIntroReq::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool TokenIntroReq::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "TokenIntroReq" : pathPrefix;

                    
    return success;
}

bool TokenIntroReq::operator==(const TokenIntroReq& rhs) const
{
    return
    
    
    (getAccessToken() == rhs.getAccessToken())
     &&
    
    (getXappInstanceId() == rhs.getXappInstanceId())
     &&
    
    (getTargetxAppId() == rhs.getTargetxAppId())
     &&
    
    
    ((!hxrfTokenIntroUriIsSet() && !rhs.hxrfTokenIntroUriIsSet()) || (hxrfTokenIntroUriIsSet() && rhs.hxrfTokenIntroUriIsSet() && getHxrfTokenIntroUri() == rhs.getHxrfTokenIntroUri()))
    
    ;
}

bool TokenIntroReq::operator!=(const TokenIntroReq& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const TokenIntroReq& o)
{
    j = nlohmann::json();
    j["accessToken"] = o.m_AccessToken;
    j["xappInstanceId"] = o.m_XappInstanceId;
    j["targetxAppId"] = o.m_TargetxAppId;
    if(o.hxrfTokenIntroUriIsSet())
        j["hxrfTokenIntroUri"] = o.m_HxrfTokenIntroUri;
    
}

void from_json(const nlohmann::json& j, TokenIntroReq& o)
{
    j.at("accessToken").get_to(o.m_AccessToken);
    j.at("xappInstanceId").get_to(o.m_XappInstanceId);
    j.at("targetxAppId").get_to(o.m_TargetxAppId);
    if(j.find("hxrfTokenIntroUri") != j.end())
    {
        j.at("hxrfTokenIntroUri").get_to(o.m_HxrfTokenIntroUri);
        o.m_HxrfTokenIntroUriIsSet = true;
    } 
    
}

std::string TokenIntroReq::getAccessToken() const
{
    return m_AccessToken;
}
void TokenIntroReq::setAccessToken(std::string const& value)
{
    m_AccessToken = value;
}
std::string TokenIntroReq::getXappInstanceId() const
{
    return m_XappInstanceId;
}
void TokenIntroReq::setXappInstanceId(std::string const& value)
{
    m_XappInstanceId = value;
}
std::string TokenIntroReq::getTargetxAppId() const
{
    return m_TargetxAppId;
}
void TokenIntroReq::setTargetxAppId(std::string const& value)
{
    m_TargetxAppId = value;
}
std::string TokenIntroReq::getHxrfTokenIntroUri() const
{
    return m_HxrfTokenIntroUri;
}
void TokenIntroReq::setHxrfTokenIntroUri(std::string const& value)
{
    m_HxrfTokenIntroUri = value;
    m_HxrfTokenIntroUriIsSet = true;
}
bool TokenIntroReq::hxrfTokenIntroUriIsSet() const
{
    return m_HxrfTokenIntroUriIsSet;
}
void TokenIntroReq::unsetHxrfTokenIntroUri()
{
    m_HxrfTokenIntroUriIsSet = false;
}


} // namespace xrf::model
