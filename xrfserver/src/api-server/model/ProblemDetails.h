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
 * ProblemDetails.h
 *
 * Provides additional information in an error response.
 */

#ifndef ProblemDetails_H_
#define ProblemDetails_H_


#include <string>
#include <nlohmann/json.hpp>

namespace xrf::model
{

/// <summary>
/// Provides additional information in an error response.
/// </summary>
class  ProblemDetails
{
public:
    ProblemDetails();
    virtual ~ProblemDetails() = default;


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

    bool operator==(const ProblemDetails& rhs) const;
    bool operator!=(const ProblemDetails& rhs) const;

    /////////////////////////////////////////////
    /// ProblemDetails members

    /// <summary>
    /// String providing an URI formatted according to RFC 3986
    /// </summary>
    std::string getType() const;
    void setType(std::string const& value);
    bool typeIsSet() const;
    void unsetType();
    /// <summary>
    /// 
    /// </summary>
    std::string getTitle() const;
    void setTitle(std::string const& value);
    bool titleIsSet() const;
    void unsetTitle();
    /// <summary>
    /// 
    /// </summary>
    int32_t getStatus() const;
    void setStatus(int32_t const value);
    bool statusIsSet() const;
    void unsetStatus();
    /// <summary>
    /// A human-readable explanation specific to this occurrence of the problem.
    /// </summary>
    std::string getDetail() const;
    void setDetail(std::string const& value);
    bool detailIsSet() const;
    void unsetDetail();
    /// <summary>
    /// String providing an URI formatted according to RFC 3986
    /// </summary>
    std::string getInstance() const;
    void setInstance(std::string const& value);
    bool instanceIsSet() const;
    void unsetInstance();

    friend void to_json(nlohmann::json& j, const ProblemDetails& o);
    friend void from_json(const nlohmann::json& j, ProblemDetails& o);
protected:
    std::string m_Type;
    bool m_TypeIsSet;
    std::string m_Title;
    bool m_TitleIsSet;
    int32_t m_Status;
    bool m_StatusIsSet;
    std::string m_Detail;
    bool m_DetailIsSet;
    std::string m_Instance;
    bool m_InstanceIsSet;
    
};

} // namespace xrf::model

#endif /* ProblemDetails_H_ */
