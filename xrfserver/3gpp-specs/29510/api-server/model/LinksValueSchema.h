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
 * LinksValueSchema.h
 *
 * A list of mutually exclusive alternatives of 1 or more links
 */

#ifndef LinksValueSchema_H_
#define LinksValueSchema_H_


#include <string>
#include "Link.h"
#include <nlohmann/json.hpp>

namespace org::openapitools::server::model
{

/// <summary>
/// A list of mutually exclusive alternatives of 1 or more links
/// </summary>
class  LinksValueSchema
{
public:
    LinksValueSchema();
    virtual ~LinksValueSchema() = default;


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

    bool operator==(const LinksValueSchema& rhs) const;
    bool operator!=(const LinksValueSchema& rhs) const;

    /////////////////////////////////////////////
    /// LinksValueSchema members

    /// <summary>
    /// String providing an URI formatted according to RFC 3986
    /// </summary>
    std::string getHref() const;
    void setHref(std::string const& value);
    bool hrefIsSet() const;
    void unsetHref();

    friend void to_json(nlohmann::json& j, const LinksValueSchema& o);
    friend void from_json(const nlohmann::json& j, LinksValueSchema& o);
protected:
    std::string m_Href;
    bool m_HrefIsSet;
    
};

} // namespace org::openapitools::server::model

#endif /* LinksValueSchema_H_ */
