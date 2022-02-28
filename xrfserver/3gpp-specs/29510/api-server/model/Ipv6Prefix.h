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
 * Ipv6Prefix.h
 *
 * String identifying an IPv6 address prefix formatted according to clause 4 of RFC 5952. IPv6Prefix data type may contain an individual /128 IPv6 address.
 */

#ifndef Ipv6Prefix_H_
#define Ipv6Prefix_H_


#include <nlohmann/json.hpp>

namespace org::openapitools::server::model
{

/// <summary>
/// String identifying an IPv6 address prefix formatted according to clause 4 of RFC 5952. IPv6Prefix data type may contain an individual /128 IPv6 address.
/// </summary>
class  Ipv6Prefix
{
public:
    Ipv6Prefix();
    virtual ~Ipv6Prefix() = default;


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

    bool operator==(const Ipv6Prefix& rhs) const;
    bool operator!=(const Ipv6Prefix& rhs) const;

    /////////////////////////////////////////////
    /// Ipv6Prefix members


    friend void to_json(nlohmann::json& j, const Ipv6Prefix& o);
    friend void from_json(const nlohmann::json& j, Ipv6Prefix& o);
protected:
    
};

} // namespace org::openapitools::server::model

#endif /* Ipv6Prefix_H_ */
