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
 * NFType_anyOf.h
 *
 * 
 */

#ifndef NFType_anyOf_H_
#define NFType_anyOf_H_


#include <nlohmann/json.hpp>

namespace org::openapitools::server::model
{

/// <summary>
/// 
/// </summary>
class  NFType_anyOf
{
public:
    NFType_anyOf();
    virtual ~NFType_anyOf() = default;

    enum class eNFType_anyOf {
    // To have a valid default value.
    // Avoiding name clashes with user defined
    // enum values
    INVALID_VALUE_OPENAPI_GENERATED = 0,
    NRF, 
    UDM, 
    AMF, 
    SMF, 
    AUSF, 
    NEF, 
    PCF, 
    SMSF, 
    NSSF, 
    UDR, 
    LMF, 
    GMLC, 
    _5G_EIR, 
    SEPP, 
    UPF, 
    N3IWF, 
    AF, 
    UDSF, 
    BSF, 
    CHF, 
    NWDAF, 
    PCSCF, 
    CBCF, 
    HSS, 
    UCMF, 
    SOR_AF, 
    SPAF, 
    MME, 
    SCSAS, 
    SCEF, 
    SCP, 
    NSSAAF, 
    ICSCF, 
    SCSCF, 
    DRA, 
    IMS_AS, 
    AANF, 
    _5G_DDNMF, 
    NSACF, 
    MFAF, 
    EASDF, 
    DCCF, 
    MB_SMF, 
    TSCTSF, 
    ADRF, 
    GBA_BSF, 
    CEF, 
    MB_UPF
    };

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

    bool operator==(const NFType_anyOf& rhs) const;
    bool operator!=(const NFType_anyOf& rhs) const;

    /////////////////////////////////////////////
    /// NFType_anyOf members

    NFType_anyOf::eNFType_anyOf getValue() const;
    void setValue(NFType_anyOf::eNFType_anyOf value);
    
    friend void to_json(nlohmann::json& j, const NFType_anyOf& o);
    friend void from_json(const nlohmann::json& j, NFType_anyOf& o);
protected:
    NFType_anyOf::eNFType_anyOf m_value = NFType_anyOf::eNFType_anyOf::INVALID_VALUE_OPENAPI_GENERATED;
};

} // namespace org::openapitools::server::model

#endif /* NFType_anyOf_H_ */