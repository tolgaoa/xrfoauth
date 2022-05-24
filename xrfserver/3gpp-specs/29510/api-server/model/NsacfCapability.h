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
/*
 * NsacfCapability.h
 *
 * 
 */

#ifndef NsacfCapability_H_
#define NsacfCapability_H_


#include <nlohmann/json.hpp>

namespace org::openapitools::server::model
{

/// <summary>
/// 
/// </summary>
class  NsacfCapability
{
public:
    NsacfCapability();
    virtual ~NsacfCapability() = default;


    /// <summary>
    /// Validate the current data in the model. Throws a ValidationException on failure.
    /// </summary>
    void validate() const;

    /// <summary>
    /// Validate the current data in the model. Returns false on error and writes an error
    /// message into the given stringstream.
    /// </summary>
    bool validate(std::stringstream& msg) const;

    /// <summary>
    /// Helper overload for validate. Used when one model stores another model and calls it's validate.
    /// Not meant to be called outside that case.
    /// </summary>
    bool validate(std::stringstream& msg, const std::string& pathPrefix) const;

    bool operator==(const NsacfCapability& rhs) const;
    bool operator!=(const NsacfCapability& rhs) const;

    /////////////////////////////////////////////
    /// NsacfCapability members

    /// <summary>
    /// Indicates the service capability of the NSACF to monitor and control the number of registered UEs per network slice for the network slice that is subject to NSAC true: Supported false (default): Not Supported 
    /// </summary>
    bool isSupportUeSAC() const;
    void setSupportUeSAC(bool const value);
    bool supportUeSACIsSet() const;
    void unsetSupportUeSAC();
    /// <summary>
    /// Indicates the service capability of the NSACF to monitor and control the number of established PDU sessions per network slice for the network slice that is subject to NSAC true: Supported false (default): Not Supported 
    /// </summary>
    bool isSupportPduSAC() const;
    void setSupportPduSAC(bool const value);
    bool supportPduSACIsSet() const;
    void unsetSupportPduSAC();

    friend void to_json(nlohmann::json& j, const NsacfCapability& o);
    friend void from_json(const nlohmann::json& j, NsacfCapability& o);
protected:
    bool m_SupportUeSAC;
    bool m_SupportUeSACIsSet;
    bool m_SupportPduSAC;
    bool m_SupportPduSACIsSet;
    
};

} // namespace org::openapitools::server::model

#endif /* NsacfCapability_H_ */