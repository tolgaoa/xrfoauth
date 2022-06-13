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
/*
 * Link.h
 *
 * It contains the URI of the linked resource.
 */

#ifndef Link_H_
#define Link_H_


#include <string>
#include <nlohmann/json.hpp>

namespace org::openapitools::server::model
{

/// <summary>
/// It contains the URI of the linked resource.
/// </summary>
class  Link
{
public:
    Link();
    virtual ~Link() = default;


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

    bool operator==(const Link& rhs) const;
    bool operator!=(const Link& rhs) const;

    /////////////////////////////////////////////
    /// Link members

    /// <summary>
    /// String providing an URI formatted according to RFC 3986
    /// </summary>
    std::string getHref() const;
    void setHref(std::string const& value);
    bool hrefIsSet() const;
    void unsetHref();

    friend void to_json(nlohmann::json& j, const Link& o);
    friend void from_json(const nlohmann::json& j, Link& o);
protected:
    std::string m_Href;
    bool m_HrefIsSet;
    
};

} // namespace org::openapitools::server::model

#endif /* Link_H_ */
