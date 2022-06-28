/**
* XRFc Service test API
* XRFc service testing API 
*
* The version of the OpenAPI document: 1
* Contact: tolgaoa@vt.edu
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/


#include "ServTestRsp.h"
#include "Helpers.h"

#include <sstream>

namespace xrf::model
{

ServTestRsp::ServTestRsp()
{
    m_ChallengeIsSet = false;
    
}

void ServTestRsp::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw xrf::helpers::ValidationException(msg.str());
    }
}

bool ServTestRsp::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool ServTestRsp::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "ServTestRsp" : pathPrefix;

        
    return success;
}

bool ServTestRsp::operator==(const ServTestRsp& rhs) const
{
    return true;
    
    
    
    
}

bool ServTestRsp::operator!=(const ServTestRsp& rhs) const
{
    return !(*this == rhs);
}

} // namespace xrf::model

