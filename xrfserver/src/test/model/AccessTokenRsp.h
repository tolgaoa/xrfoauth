/**
* XRF OAuth2 Token Request API
* XRF OAuth2 Authorization server, token generation API 
*
* The version of the OpenAPI document: 1
* Contact: tolgaoa@vt.edu
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/
/*
 * AccessTokenRsp.h
 *
 * Contains information related to the access token response
 */

#ifndef AccessTokenRsp_H_
#define AccessTokenRsp_H_


#include <string>
#include <nlohmann/json.hpp>

namespace org::openapitools::server::model
{

/// <summary>
/// Contains information related to the access token response
/// </summary>
class  AccessTokenRsp
{
public:
    AccessTokenRsp();
    virtual ~AccessTokenRsp() = default;


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

    bool operator==(const AccessTokenRsp& rhs) const;
    bool operator!=(const AccessTokenRsp& rhs) const;

    /////////////////////////////////////////////
    /// AccessTokenRsp members

    /// <summary>
    /// JWS Compact Serialized representation of JWS signed JSON object (AccessTokenClaims)
    /// </summary>
    std::string getAccessToken() const;
    void setAccessToken(std::string const& value);
    /// <summary>
    /// 
    /// </summary>
    std::string getTokenType() const;
    void setTokenType(std::string const& value);
    /// <summary>
    /// 
    /// </summary>
    int32_t getExpiresIn() const;
    void setExpiresIn(int32_t const value);
    bool expiresInIsSet() const;
    void unsetExpires_in();
    /// <summary>
    /// 
    /// </summary>
    std::string getScope() const;
    void setScope(std::string const& value);
    bool scopeIsSet() const;
    void unsetScope();

    friend void to_json(nlohmann::json& j, const AccessTokenRsp& o);
    friend void from_json(const nlohmann::json& j, AccessTokenRsp& o);
protected:
    std::string m_Access_token;

    std::string m_Token_type;

    int32_t m_Expires_in;
    bool m_Expires_inIsSet;
    std::string m_Scope;
    bool m_ScopeIsSet;
    
};

} // namespace org::openapitools::server::model

#endif /* AccessTokenRsp_H_ */
