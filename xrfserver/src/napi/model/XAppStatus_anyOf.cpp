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


#include "XAppStatus_anyOf.h"
#include "Helpers.h"
#include <stdexcept>
#include <sstream>

namespace org::openapitools::server::model
{

XAppStatus_anyOf::XAppStatus_anyOf()
{
    
}

void XAppStatus_anyOf::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::openapitools::server::helpers::ValidationException(msg.str());
    }
}

bool XAppStatus_anyOf::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool XAppStatus_anyOf::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "XAppStatus_anyOf" : pathPrefix;

    
    if (m_value == XAppStatus_anyOf::eXAppStatus_anyOf::INVALID_VALUE_OPENAPI_GENERATED)
    {
        success = false;
        msg << _pathPrefix << ": has no value;";
    }

    return success;
}

bool XAppStatus_anyOf::operator==(const XAppStatus_anyOf& rhs) const
{
    return
    getValue() == rhs.getValue()
    
    ;
}

bool XAppStatus_anyOf::operator!=(const XAppStatus_anyOf& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const XAppStatus_anyOf& o)
{
    j = nlohmann::json();
    
    switch (o.getValue())
    {
        case XAppStatus_anyOf::eXAppStatus_anyOf::INVALID_VALUE_OPENAPI_GENERATED:
            j = "INVALID_VALUE_OPENAPI_GENERATED";
            break;
        case XAppStatus_anyOf::eXAppStatus_anyOf::REGISTERED:
            j = "REGISTERED";
            break;
        case XAppStatus_anyOf::eXAppStatus_anyOf::SUSPENDED:
            j = "SUSPENDED";
            break;
        case XAppStatus_anyOf::eXAppStatus_anyOf::UNDISCOVERABLE:
            j = "UNDISCOVERABLE";
            break;
    }
}

void from_json(const nlohmann::json& j, XAppStatus_anyOf& o)
{
    
    auto s = j.get<std::string>();
    if (s == "REGISTERED") {
     o.setValue(XAppStatus_anyOf::eXAppStatus_anyOf::REGISTERED);
    } 
    else if (s == "SUSPENDED") {
     o.setValue(XAppStatus_anyOf::eXAppStatus_anyOf::SUSPENDED);
    } 
    else if (s == "UNDISCOVERABLE") {
     o.setValue(XAppStatus_anyOf::eXAppStatus_anyOf::UNDISCOVERABLE);
    }  else {
     std::stringstream ss;
     ss << "Unexpected value " << s << " in json"
        << " cannot be converted to enum of type"
        << " XAppStatus_anyOf::eXAppStatus_anyOf";
     throw std::invalid_argument(ss.str());
    } 

}

XAppStatus_anyOf::eXAppStatus_anyOf XAppStatus_anyOf::getValue() const
{
    return m_value;
}
void XAppStatus_anyOf::setValue(XAppStatus_anyOf::eXAppStatus_anyOf value)
{
    m_value = value;
}

} // namespace org::openapitools::server::model

