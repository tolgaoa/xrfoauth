/**
* XRF OAuth2
* XRF OAuth2 Authorization server for generating access tokens to xApps 
*
* The version of the OpenAPI document: 1
* Contact: tolgaoa@vt.edu
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/
/*
 * AccessTokenErr.h
 *
 * Error returned in the access token response message
 */

#ifndef AccessTokenErr_H_
#define AccessTokenErr_H_


#include <string>
#include <nlohmann/json.hpp>

namespace xrf::model
{

/// <summary>
/// Error returned in the access token response message
/// </summary>
class  AccessTokenErr
{
public:
    AccessTokenErr();
    virtual ~AccessTokenErr() = default;


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

    bool operator==(const AccessTokenErr& rhs) const;
    bool operator!=(const AccessTokenErr& rhs) const;

    /////////////////////////////////////////////
    /// AccessTokenErr members

    /// <summary>
    /// 
    /// </summary>
    std::string getError() const;
    void setError(std::string const& value);
    /// <summary>
    /// 
    /// </summary>
    std::string getErrorDescription() const;
    void setErrorDescription(std::string const& value);
    bool errorDescriptionIsSet() const;
    void unsetError_description();
    /// <summary>
    /// 
    /// </summary>
    std::string getErrorUri() const;
    void setErrorUri(std::string const& value);
    bool errorUriIsSet() const;
    void unsetError_uri();

    friend void to_json(nlohmann::json& j, const AccessTokenErr& o);
    friend void from_json(const nlohmann::json& j, AccessTokenErr& o);
protected:
    std::string m_Error;

    std::string m_Error_description;
    bool m_Error_descriptionIsSet;
    std::string m_Error_uri;
    bool m_Error_uriIsSet;
    
};

} // namespace org::openapitools::server::model

#endif /* AccessTokenErr_H_ */
