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


#include "XAppDiscErr.h"
#include "Helpers.h"

#include <sstream>

namespace xrf::model
{

XAppDiscErr::XAppDiscErr()
{
    m_Error = "";
    m_Error_description = "";
    m_Error_descriptionIsSet = false;
    m_Error_uri = "";
    m_Error_uriIsSet = false;
    
}

void XAppDiscErr::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw xrf::helpers::ValidationException(msg.str());
    }
}

bool XAppDiscErr::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool XAppDiscErr::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "XAppDiscErr" : pathPrefix;

                
    return success;
}

bool XAppDiscErr::operator==(const XAppDiscErr& rhs) const
{
    return
    
    
    (getError() == rhs.getError())
     &&
    
    
    ((!errorDescriptionIsSet() && !rhs.errorDescriptionIsSet()) || (errorDescriptionIsSet() && rhs.errorDescriptionIsSet() && getErrorDescription() == rhs.getErrorDescription())) &&
    
    
    ((!errorUriIsSet() && !rhs.errorUriIsSet()) || (errorUriIsSet() && rhs.errorUriIsSet() && getErrorUri() == rhs.getErrorUri()))
    
    ;
}

bool XAppDiscErr::operator!=(const XAppDiscErr& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const XAppDiscErr& o)
{
    j = nlohmann::json();
    j["error"] = o.m_Error;
    if(o.errorDescriptionIsSet())
        j["error_description"] = o.m_Error_description;
    if(o.errorUriIsSet())
        j["error_uri"] = o.m_Error_uri;
    
}

void from_json(const nlohmann::json& j, XAppDiscErr& o)
{
    j.at("error").get_to(o.m_Error);
    if(j.find("error_description") != j.end())
    {
        j.at("error_description").get_to(o.m_Error_description);
        o.m_Error_descriptionIsSet = true;
    } 
    if(j.find("error_uri") != j.end())
    {
        j.at("error_uri").get_to(o.m_Error_uri);
        o.m_Error_uriIsSet = true;
    } 
    
}

std::string XAppDiscErr::getError() const
{
    return m_Error;
}
void XAppDiscErr::setError(std::string const& value)
{
    m_Error = value;
}
std::string XAppDiscErr::getErrorDescription() const
{
    return m_Error_description;
}
void XAppDiscErr::setErrorDescription(std::string const& value)
{
    m_Error_description = value;
    m_Error_descriptionIsSet = true;
}
bool XAppDiscErr::errorDescriptionIsSet() const
{
    return m_Error_descriptionIsSet;
}
void XAppDiscErr::unsetError_description()
{
    m_Error_descriptionIsSet = false;
}
std::string XAppDiscErr::getErrorUri() const
{
    return m_Error_uri;
}
void XAppDiscErr::setErrorUri(std::string const& value)
{
    m_Error_uri = value;
    m_Error_uriIsSet = true;
}
bool XAppDiscErr::errorUriIsSet() const
{
    return m_Error_uriIsSet;
}
void XAppDiscErr::unsetError_uri()
{
    m_Error_uriIsSet = false;
}


} // namespace xrf::model

