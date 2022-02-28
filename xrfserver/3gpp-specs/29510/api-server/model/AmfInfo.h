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
 * AmfInfo.h
 *
 * Information of an AMF NF Instance
 */

#ifndef AmfInfo_H_
#define AmfInfo_H_


#include "N2InterfaceAmfInfo.h"
#include "Tai.h"
#include <string>
#include "TaiRange.h"
#include <vector>
#include "Guami.h"
#include <nlohmann/json.hpp>

namespace org::openapitools::server::model
{

/// <summary>
/// Information of an AMF NF Instance
/// </summary>
class  AmfInfo
{
public:
    AmfInfo();
    virtual ~AmfInfo() = default;


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

    bool operator==(const AmfInfo& rhs) const;
    bool operator!=(const AmfInfo& rhs) const;

    /////////////////////////////////////////////
    /// AmfInfo members

    /// <summary>
    /// String identifying the AMF Set ID (10 bits) as specified in clause 2.10.1 of 3GPP TS 23.003. It is encoded as a string of 3 hexadecimal characters where the first character is limited to values 0 to 3 (i.e. 10 bits)
    /// </summary>
    std::string getAmfSetId() const;
    void setAmfSetId(std::string const& value);
    /// <summary>
    /// String identifying the AMF Set ID (10 bits) as specified in clause 2.10.1 of 3GPP TS 23.003. It is encoded as a string of 3 hexadecimal characters where the first character is limited to values 0 to 3 (i.e. 10 bits)
    /// </summary>
    std::string getAmfRegionId() const;
    void setAmfRegionId(std::string const& value);
    /// <summary>
    /// 
    /// </summary>
    std::vector<Guami> getGuamiList() const;
    void setGuamiList(std::vector<Guami> const& value);
    /// <summary>
    /// 
    /// </summary>
    std::vector<Tai> getTaiList() const;
    void setTaiList(std::vector<Tai> const& value);
    bool taiListIsSet() const;
    void unsetTaiList();
    /// <summary>
    /// 
    /// </summary>
    std::vector<TaiRange> getTaiRangeList() const;
    void setTaiRangeList(std::vector<TaiRange> const& value);
    bool taiRangeListIsSet() const;
    void unsetTaiRangeList();
    /// <summary>
    /// 
    /// </summary>
    std::vector<Guami> getBackupInfoAmfFailure() const;
    void setBackupInfoAmfFailure(std::vector<Guami> const& value);
    bool backupInfoAmfFailureIsSet() const;
    void unsetBackupInfoAmfFailure();
    /// <summary>
    /// 
    /// </summary>
    std::vector<Guami> getBackupInfoAmfRemoval() const;
    void setBackupInfoAmfRemoval(std::vector<Guami> const& value);
    bool backupInfoAmfRemovalIsSet() const;
    void unsetBackupInfoAmfRemoval();
    /// <summary>
    /// 
    /// </summary>
    N2InterfaceAmfInfo getN2InterfaceAmfInfo() const;
    void setN2InterfaceAmfInfo(N2InterfaceAmfInfo const& value);
    bool n2InterfaceAmfInfoIsSet() const;
    void unsetN2InterfaceAmfInfo();

    friend void to_json(nlohmann::json& j, const AmfInfo& o);
    friend void from_json(const nlohmann::json& j, AmfInfo& o);
protected:
    std::string m_AmfSetId;

    std::string m_AmfRegionId;

    std::vector<Guami> m_GuamiList;

    std::vector<Tai> m_TaiList;
    bool m_TaiListIsSet;
    std::vector<TaiRange> m_TaiRangeList;
    bool m_TaiRangeListIsSet;
    std::vector<Guami> m_BackupInfoAmfFailure;
    bool m_BackupInfoAmfFailureIsSet;
    std::vector<Guami> m_BackupInfoAmfRemoval;
    bool m_BackupInfoAmfRemovalIsSet;
    N2InterfaceAmfInfo m_N2InterfaceAmfInfo;
    bool m_N2InterfaceAmfInfoIsSet;
    
};

} // namespace org::openapitools::server::model

#endif /* AmfInfo_H_ */
