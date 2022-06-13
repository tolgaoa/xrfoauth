/**
* XRF OAuth2 xApp Discvoery API
* XRF OAuth2 Authorization server, xApp Discovery API 
*
* The version of the OpenAPI document: 1
* Contact: tolgaoa@vt.edu
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/


#include "XAppProfile.h"
#include "Helpers.h"

#include <sstream>

namespace org::openapitools::server::model
{

XAppProfile::XAppProfile()
{
    m_XAppInstanceId = "";
    m_XAppServiceIsSet = false;
    m_XAppIpv4 = "";
    
}

void XAppProfile::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::openapitools::server::helpers::ValidationException(msg.str());
    }
}

bool XAppProfile::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool XAppProfile::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "XAppProfile" : pathPrefix;

                     
    
    /* XAppIpv4 */ {
        const std::string& value = m_XAppIpv4;
        const std::string currentValuePath = _pathPrefix + ".xAppIpv4";
                
        

    }
    
    return success;
}

bool XAppProfile::operator==(const XAppProfile& rhs) const
{
    return
    
    
    (getXAppInstanceId() == rhs.getXAppInstanceId())
     &&
    
    
    ((!xAppServiceIsSet() && !rhs.xAppServiceIsSet()) || (xAppServiceIsSet() && rhs.xAppServiceIsSet() && getXAppService() == rhs.getXAppService())) &&
    
    (getXAppStatus() == rhs.getXAppStatus())
     &&
    
    (getXAppIpv4() == rhs.getXAppIpv4())
    
    
    ;
}

bool XAppProfile::operator!=(const XAppProfile& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const XAppProfile& o)
{
    j = nlohmann::json();
    j["xAppInstanceId"] = o.m_XAppInstanceId;
    if(o.xAppServiceIsSet())
        j["xAppService"] = o.m_XAppService;
    j["xAppStatus"] = o.m_XAppStatus;
    j["xAppIpv4"] = o.m_XAppIpv4;
    
}

void from_json(const nlohmann::json& j, XAppProfile& o)
{
    j.at("xAppInstanceId").get_to(o.m_XAppInstanceId);
    if(j.find("xAppService") != j.end())
    {
        j.at("xAppService").get_to(o.m_XAppService);
        o.m_XAppServiceIsSet = true;
    } 
    j.at("xAppStatus").get_to(o.m_XAppStatus);
    j.at("xAppIpv4").get_to(o.m_XAppIpv4);
    
}

std::string XAppProfile::getXAppInstanceId() const
{
    return m_XAppInstanceId;
}
void XAppProfile::setXAppInstanceId(std::string const& value)
{
    m_XAppInstanceId = value;
}
XAppService XAppProfile::getXAppService() const
{
    return m_XAppService;
}
void XAppProfile::setXAppService(XAppService const& value)
{
    m_XAppService = value;
    m_XAppServiceIsSet = true;
}
bool XAppProfile::xAppServiceIsSet() const
{
    return m_XAppServiceIsSet;
}
void XAppProfile::unsetXAppService()
{
    m_XAppServiceIsSet = false;
}
XAppStatus XAppProfile::getXAppStatus() const
{
    return m_XAppStatus;
}
void XAppProfile::setXAppStatus(XAppStatus const& value)
{
    m_XAppStatus = value;
}
std::string XAppProfile::getXAppIpv4() const
{
    return m_XAppIpv4;
}
void XAppProfile::setXAppIpv4(std::string const& value)
{
    m_XAppIpv4 = value;
}


} // namespace org::openapitools::server::model

