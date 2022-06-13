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


#include "XAppDiscRsp.h"
#include "Helpers.h"

#include <sstream>

namespace org::openapitools::server::model
{

XAppDiscRsp::XAppDiscRsp()
{
    
}

void XAppDiscRsp::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::openapitools::server::helpers::ValidationException(msg.str());
    }
}

bool XAppDiscRsp::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool XAppDiscRsp::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "XAppDiscRsp" : pathPrefix;

         
    
    /* XApplist */ {
        const std::vector<std::string>& value = m_XApplist;
        const std::string currentValuePath = _pathPrefix + ".xApplist";
                
        
        { // Recursive validation of array elements
            const std::string oldValuePath = currentValuePath;
            int i = 0;
            for (const std::string& value : value)
            { 
                const std::string currentValuePath = oldValuePath + "[" + std::to_string(i) + "]";
                        
        
 
                i++;
            }
        }

    }
    
    return success;
}

bool XAppDiscRsp::operator==(const XAppDiscRsp& rhs) const
{
    return
    
    
    (getXApplist() == rhs.getXApplist())
    
    
    ;
}

bool XAppDiscRsp::operator!=(const XAppDiscRsp& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const XAppDiscRsp& o)
{
    j = nlohmann::json();
    j["xApplist"] = o.m_XApplist;
    
}

void from_json(const nlohmann::json& j, XAppDiscRsp& o)
{
    j.at("xApplist").get_to(o.m_XApplist);
    
}

std::vector<std::string> XAppDiscRsp::getXApplist() const
{
    return m_XApplist;
}
void XAppDiscRsp::setXApplist(std::vector<std::string> const& value)
{
    m_XApplist = value;
}


} // namespace org::openapitools::server::model

