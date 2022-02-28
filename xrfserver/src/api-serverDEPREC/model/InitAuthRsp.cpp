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


#include "InitAuthRsp.h"
#include "Helpers.h"

#include <sstream>

namespace xrf::model
{

InitAuthRsp::InitAuthRsp()
{
    m_Challenge = "";
    m_XrfInstanceId = "";
    
}

void InitAuthRsp::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw xrf::helpers::ValidationException(msg.str());
    }
}

bool InitAuthRsp::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool InitAuthRsp::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "InitAuthRsp" : pathPrefix;

            
    return success;
}

bool InitAuthRsp::operator==(const InitAuthRsp& rhs) const
{
    return
    
    
    (getChallenge() == rhs.getChallenge())
     &&
    
    (getXrfInstanceId() == rhs.getXrfInstanceId())
    
    
    ;
}

bool InitAuthRsp::operator!=(const InitAuthRsp& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const InitAuthRsp& o)
{
    j = nlohmann::json();
    j["challenge"] = o.m_Challenge;
    j["xrfInstanceId"] = o.m_XrfInstanceId;
    
}

void from_json(const nlohmann::json& j, InitAuthRsp& o)
{
    j.at("challenge").get_to(o.m_Challenge);
    j.at("xrfInstanceId").get_to(o.m_XrfInstanceId);
    
}

std::string InitAuthRsp::getChallenge() const
{
    return m_Challenge;
}
void InitAuthRsp::setChallenge(std::string const& value)
{
    m_Challenge = value;
}
std::string InitAuthRsp::getXrfInstanceId() const
{
    return m_XrfInstanceId;
}
void InitAuthRsp::setXrfInstanceId(std::string const& value)
{
    m_XrfInstanceId = value;
}


} // namespace xrf::model

