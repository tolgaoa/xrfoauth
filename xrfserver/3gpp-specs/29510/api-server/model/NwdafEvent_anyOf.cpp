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


#include "NwdafEvent_anyOf.h"
#include "Helpers.h"
#include <stdexcept>
#include <sstream>

namespace org::openapitools::server::model
{

NwdafEvent_anyOf::NwdafEvent_anyOf()
{
    
}

void NwdafEvent_anyOf::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::openapitools::server::helpers::ValidationException(msg.str());
    }
}

bool NwdafEvent_anyOf::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool NwdafEvent_anyOf::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "NwdafEvent_anyOf" : pathPrefix;

    
    if (m_value == NwdafEvent_anyOf::eNwdafEvent_anyOf::INVALID_VALUE_OPENAPI_GENERATED)
    {
        success = false;
        msg << _pathPrefix << ": has no value;";
    }

    return success;
}

bool NwdafEvent_anyOf::operator==(const NwdafEvent_anyOf& rhs) const
{
    return
    getValue() == rhs.getValue()
    
    ;
}

bool NwdafEvent_anyOf::operator!=(const NwdafEvent_anyOf& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const NwdafEvent_anyOf& o)
{
    j = nlohmann::json();
    
    switch (o.getValue())
    {
        case NwdafEvent_anyOf::eNwdafEvent_anyOf::INVALID_VALUE_OPENAPI_GENERATED:
            j = "INVALID_VALUE_OPENAPI_GENERATED";
            break;
        case NwdafEvent_anyOf::eNwdafEvent_anyOf::SLICE_LOAD_LEVEL:
            j = "SLICE_LOAD_LEVEL";
            break;
        case NwdafEvent_anyOf::eNwdafEvent_anyOf::NETWORK_PERFORMANCE:
            j = "NETWORK_PERFORMANCE";
            break;
        case NwdafEvent_anyOf::eNwdafEvent_anyOf::NF_LOAD:
            j = "NF_LOAD";
            break;
        case NwdafEvent_anyOf::eNwdafEvent_anyOf::SERVICE_EXPERIENCE:
            j = "SERVICE_EXPERIENCE";
            break;
        case NwdafEvent_anyOf::eNwdafEvent_anyOf::UE_MOBILITY:
            j = "UE_MOBILITY";
            break;
        case NwdafEvent_anyOf::eNwdafEvent_anyOf::UE_COMMUNICATION:
            j = "UE_COMMUNICATION";
            break;
        case NwdafEvent_anyOf::eNwdafEvent_anyOf::QOS_SUSTAINABILITY:
            j = "QOS_SUSTAINABILITY";
            break;
        case NwdafEvent_anyOf::eNwdafEvent_anyOf::ABNORMAL_BEHAVIOUR:
            j = "ABNORMAL_BEHAVIOUR";
            break;
        case NwdafEvent_anyOf::eNwdafEvent_anyOf::USER_DATA_CONGESTION:
            j = "USER_DATA_CONGESTION";
            break;
        case NwdafEvent_anyOf::eNwdafEvent_anyOf::NSI_LOAD_LEVEL:
            j = "NSI_LOAD_LEVEL";
            break;
        case NwdafEvent_anyOf::eNwdafEvent_anyOf::DN_PERFORMANCE:
            j = "DN_PERFORMANCE";
            break;
    }
}

void from_json(const nlohmann::json& j, NwdafEvent_anyOf& o)
{
    
    auto s = j.get<std::string>();
    if (s == "SLICE_LOAD_LEVEL") {
     o.setValue(NwdafEvent_anyOf::eNwdafEvent_anyOf::SLICE_LOAD_LEVEL);
    } 
    else if (s == "NETWORK_PERFORMANCE") {
     o.setValue(NwdafEvent_anyOf::eNwdafEvent_anyOf::NETWORK_PERFORMANCE);
    } 
    else if (s == "NF_LOAD") {
     o.setValue(NwdafEvent_anyOf::eNwdafEvent_anyOf::NF_LOAD);
    } 
    else if (s == "SERVICE_EXPERIENCE") {
     o.setValue(NwdafEvent_anyOf::eNwdafEvent_anyOf::SERVICE_EXPERIENCE);
    } 
    else if (s == "UE_MOBILITY") {
     o.setValue(NwdafEvent_anyOf::eNwdafEvent_anyOf::UE_MOBILITY);
    } 
    else if (s == "UE_COMMUNICATION") {
     o.setValue(NwdafEvent_anyOf::eNwdafEvent_anyOf::UE_COMMUNICATION);
    } 
    else if (s == "QOS_SUSTAINABILITY") {
     o.setValue(NwdafEvent_anyOf::eNwdafEvent_anyOf::QOS_SUSTAINABILITY);
    } 
    else if (s == "ABNORMAL_BEHAVIOUR") {
     o.setValue(NwdafEvent_anyOf::eNwdafEvent_anyOf::ABNORMAL_BEHAVIOUR);
    } 
    else if (s == "USER_DATA_CONGESTION") {
     o.setValue(NwdafEvent_anyOf::eNwdafEvent_anyOf::USER_DATA_CONGESTION);
    } 
    else if (s == "NSI_LOAD_LEVEL") {
     o.setValue(NwdafEvent_anyOf::eNwdafEvent_anyOf::NSI_LOAD_LEVEL);
    } 
    else if (s == "DN_PERFORMANCE") {
     o.setValue(NwdafEvent_anyOf::eNwdafEvent_anyOf::DN_PERFORMANCE);
    }  else {
     std::stringstream ss;
     ss << "Unexpected value " << s << " in json"
        << " cannot be converted to enum of type"
        << " NwdafEvent_anyOf::eNwdafEvent_anyOf";
     throw std::invalid_argument(ss.str());
    } 

}

NwdafEvent_anyOf::eNwdafEvent_anyOf NwdafEvent_anyOf::getValue() const
{
    return m_value;
}
void NwdafEvent_anyOf::setValue(NwdafEvent_anyOf::eNwdafEvent_anyOf value)
{
    m_value = value;
}

} // namespace org::openapitools::server::model
