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
 * PatchItem.h
 *
 * it contains information on data to be changed.
 */

#ifndef PatchItem_H_
#define PatchItem_H_


#include <string>
#include "AnyType.h"
#include <nlohmann/json.hpp>

namespace org::openapitools::server::model
{

/// <summary>
/// it contains information on data to be changed.
/// </summary>
class  PatchItem
{
public:
    PatchItem();
    virtual ~PatchItem() = default;


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

    bool operator==(const PatchItem& rhs) const;
    bool operator!=(const PatchItem& rhs) const;

    /////////////////////////////////////////////
    /// PatchItem members

    /// <summary>
    /// indicates the patch operation as defined in IETF RFC 6902 to be performed on the resource.
    /// </summary>
    AnyType getOp() const;
    void setOp(AnyType const& value);
    /// <summary>
    /// contains a JSON pointer value (as defined in IETF RFC 6901) that references a location of a resource on which the patch operation shall be performed.
    /// </summary>
    std::string getPath() const;
    void setPath(std::string const& value);
    /// <summary>
    /// indicates the path of the source JSON element (according to JSON Pointer syntax) being moved or copied to the location indicated by the \&quot;path\&quot; attribute.
    /// </summary>
    std::string getFrom() const;
    void setFrom(std::string const& value);
    bool fromIsSet() const;
    void unsetFrom();
    /// <summary>
    /// 
    /// </summary>
    AnyType getValue() const;
    void setValue(AnyType const& value);
    bool valueIsSet() const;
    void unsetValue();

    friend void to_json(nlohmann::json& j, const PatchItem& o);
    friend void from_json(const nlohmann::json& j, PatchItem& o);
protected:
    AnyType m_Op;

    std::string m_Path;

    std::string m_From;
    bool m_FromIsSet;
    AnyType m_Value;
    bool m_ValueIsSet;
    
};

} // namespace org::openapitools::server::model

#endif /* PatchItem_H_ */
