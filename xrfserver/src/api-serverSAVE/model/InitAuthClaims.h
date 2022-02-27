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
 * InitAuthClaims.h
 *
 * The claims data structure for the initial authentication request
 */

#ifndef InitAuthClaims_H_
#define InitAuthClaims_H_


#include <string>
#include <nlohmann/json.hpp>

namespace xrf::model
{

/// <summary>
/// The claims data structure for the initial authentication request
/// </summary>
class  InitAuthClaims
{
public:
    InitAuthClaims();
    virtual ~InitAuthClaims() = default;


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

    bool operator==(const InitAuthClaims& rhs) const;
    bool operator!=(const InitAuthClaims& rhs) const;

    /////////////////////////////////////////////
    /// InitAuthClaims members

    /// <summary>
    /// 
    /// </summary>
    std::string getRootCA() const;
    void setRootCA(std::string const& value);
    /// <summary>
    /// 
    /// </summary>
    std::string getPubkey() const;
    void setPubkey(std::string const& value);
    /// <summary>
    /// 
    /// </summary>
    std::string getIdentity() const;
    void setIdentity(std::string const& value);

    friend void to_json(nlohmann::json& j, const InitAuthClaims& o);
    friend void from_json(const nlohmann::json& j, InitAuthClaims& o);
protected:
    std::string m_RootCA;

    std::string m_Pubkey;

    std::string m_Identity;

    
};

} // namespace xrf::model

#endif /* InitAuthClaims_H_ */