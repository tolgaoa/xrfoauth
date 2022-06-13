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
 * XAppDiscRsp.h
 *
 * Response for initial xApp discovery for a large set
 */

#ifndef XAppDiscRsp_H_
#define XAppDiscRsp_H_


#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace xrf::model
{

/// <summary>
/// Response for initial xApp discovery for a large set
/// </summary>
class  XAppDiscRsp
{
public:
    XAppDiscRsp();
    virtual ~XAppDiscRsp() = default;


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

    bool operator==(const XAppDiscRsp& rhs) const;
    bool operator!=(const XAppDiscRsp& rhs) const;

    /////////////////////////////////////////////
    /// XAppDiscRsp members

    /// <summary>
    /// 
    /// </summary>
    std::vector<std::string> getXApplist() const;
    void setXApplist(std::vector<std::string> const& value);

    friend void to_json(nlohmann::json& j, const XAppDiscRsp& o);
    friend void from_json(const nlohmann::json& j, XAppDiscRsp& o);
protected:
    std::vector<std::string> m_XApplist;

    
};

} // namespace xrf::model

#endif /* XAppDiscRsp_H_ */
