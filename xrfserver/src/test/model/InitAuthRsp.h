/**
* XRF OAuth2 Initial Authentication Request API
* XRF OAuth2 Authorization server, initial authentication with the xApp API 
*
* The version of the OpenAPI document: 1
* Contact: tolgaoa@vt.edu
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/
/*
 * InitAuthRsp.h
 *
 * Contains information related to the initial authentication response
 */

#ifndef InitAuthRsp_H_
#define InitAuthRsp_H_


#include <string>
#include <nlohmann/json.hpp>

namespace org::openapitools::server::model
{

/// <summary>
/// Contains information related to the initial authentication response
/// </summary>
class  InitAuthRsp
{
public:
    InitAuthRsp();
    virtual ~InitAuthRsp() = default;


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

    bool operator==(const InitAuthRsp& rhs) const;
    bool operator!=(const InitAuthRsp& rhs) const;

    /////////////////////////////////////////////
    /// InitAuthRsp members

    /// <summary>
    /// Challenge for verifying the xApp that wants to authenticate
    /// </summary>
    std::string getChallenge() const;
    void setChallenge(std::string const& value);
    /// <summary>
    /// UUID specific to the XRF server
    /// </summary>
    std::string getXrfInstanceId() const;
    void setXrfInstanceId(std::string const& value);

    friend void to_json(nlohmann::json& j, const InitAuthRsp& o);
    friend void from_json(const nlohmann::json& j, InitAuthRsp& o);
protected:
    std::string m_Challenge;

    std::string m_XrfInstanceId;

    
};

} // namespace org::openapitools::server::model

#endif /* InitAuthRsp_H_ */
