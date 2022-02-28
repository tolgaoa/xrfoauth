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
 * ExtSnssai.h
 *
 * The sdRanges and wildcardSd attributes shall be exclusive from each other. If one of these attributes is present, the sd attribute shall also be present and it shall contain one Slice Differentiator value within the range of SD (if the sdRanges attribute is present) or with any value (if the wildcardSd attribute is present).
 */

#ifndef ExtSnssai_H_
#define ExtSnssai_H_


#include "SdRange.h"
#include "SnssaiExtension.h"
#include <string>
#include "Snssai.h"
#include <vector>
#include <nlohmann/json.hpp>

namespace org::openapitools::server::model
{

/// <summary>
/// The sdRanges and wildcardSd attributes shall be exclusive from each other. If one of these attributes is present, the sd attribute shall also be present and it shall contain one Slice Differentiator value within the range of SD (if the sdRanges attribute is present) or with any value (if the wildcardSd attribute is present).
/// </summary>
class  ExtSnssai
{
public:
    ExtSnssai();
    virtual ~ExtSnssai() = default;


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

    bool operator==(const ExtSnssai& rhs) const;
    bool operator!=(const ExtSnssai& rhs) const;

    /////////////////////////////////////////////
    /// ExtSnssai members

    /// <summary>
    /// Unsigned integer, within the range 0 to 255, representing the Slice/Service Type. It indicates the expected Network Slice behaviour in terms of features and services.  Values 0 to 127 correspond to the standardized SST range. Values 128 to 255 correspond to the Operator-specific range. See clause 28.4.2 of 3GPP TS 23.003.  Standardized values are defined in clause 5.15.2.2 of 3GPP TS 23.501. 
    /// </summary>
    int32_t getSst() const;
    void setSst(int32_t const value);
    /// <summary>
    /// 3-octet string, representing the Slice Differentiator, in hexadecimal representation. Each character in the string shall take a value of \&quot;0\&quot; to \&quot;9\&quot;, \&quot;a\&quot; to \&quot;f\&quot; or \&quot;A\&quot; to \&quot;F\&quot; and shall represent 4 bits. The most significant character representing the 4 most significant bits of the SD shall appear first in the string, and the character representing the 4 least significant bit of the SD shall appear last in the string.  This is an optional parameter that complements the Slice/Service type(s) to allow to differentiate amongst multiple Network Slices of the same Slice/Service type. This IE shall be absent if no SD value is associated with the SST. 
    /// </summary>
    std::string getSd() const;
    void setSd(std::string const& value);
    bool sdIsSet() const;
    void unsetSd();
    /// <summary>
    /// When present, it shall contain the range(s) of Slice Differentiator values supported for the Slice/Service Type value indicated in the sst attribute of the Snssai data type
    /// </summary>
    std::vector<SdRange> getSdRanges() const;
    void setSdRanges(std::vector<SdRange> const& value);
    bool sdRangesIsSet() const;
    void unsetSdRanges();
    /// <summary>
    /// When present, it shall be set to true, to indicate that all SD values are supported for the Slice/Service Type value indicated in the sst attribute of the Snssai data type
    /// </summary>
    bool isWildcardSd() const;
    void setWildcardSd(bool const value);
    bool wildcardSdIsSet() const;
    void unsetWildcardSd();

    friend void to_json(nlohmann::json& j, const ExtSnssai& o);
    friend void from_json(const nlohmann::json& j, ExtSnssai& o);
protected:
    int32_t m_Sst;

    std::string m_Sd;
    bool m_SdIsSet;
    std::vector<SdRange> m_SdRanges;
    bool m_SdRangesIsSet;
    bool m_WildcardSd;
    bool m_WildcardSdIsSet;
    
};

} // namespace org::openapitools::server::model

#endif /* ExtSnssai_H_ */
