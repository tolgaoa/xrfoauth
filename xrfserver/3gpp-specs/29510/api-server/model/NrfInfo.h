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
 * NrfInfo.h
 *
 * Information of an NRF NF Instance, used in hierarchical NRF deployments
 */

#ifndef NrfInfo_H_
#define NrfInfo_H_


#include "AnyOfUpfInfoobject.h"
#include "AnyOfMbSmfInfoobject.h"
#include "AnyOfAmfInfoobject.h"
#include "AnyOfNefInfoobject.h"
#include "AnyOfSeppInfoobject.h"
#include "AnyOfGmlcInfoobject.h"
#include "AnyOfUdmInfoobject.h"
#include "AnyOfUdsfInfoobject.h"
#include "AnyOfBsfInfoobject.h"
#include "AnyOfScpInfoobject.h"
#include "EasdfInfo.h"
#include "AnyOfNwdafInfoobject.h"
#include "AnyOfSmfInfoobject.h"
#include <map>
#include "AnyOfUdrInfoobject.h"
#include "5GDdnmfInfo.h"
#include "AnyOfAusfInfoobject.h"
#include "AnyOfChfInfoobject.h"
#include "AnyOfLmfInfoobject.h"
#include "AnyOfAanfInfoobject.h"
#include "AnyOfPcfInfoobject.h"
#include "TrustAfInfo.h"
#include <vector>
#include "MbUpfInfo.h"
#include "NfInfo.h"
#include "AnyOfHssInfoobject.h"
#include "AnyOfPcscfInfoobject.h"
#include "MfafInfo.h"
#include "TsctsfInfo.h"
#include "DccfInfo.h"
#include "NwdafInfo.h"
#include <nlohmann/json.hpp>

namespace org::openapitools::server::model
{

/// <summary>
/// Information of an NRF NF Instance, used in hierarchical NRF deployments
/// </summary>
class  NrfInfo
{
public:
    NrfInfo();
    virtual ~NrfInfo() = default;


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

    bool operator==(const NrfInfo& rhs) const;
    bool operator!=(const NrfInfo& rhs) const;

    /////////////////////////////////////////////
    /// NrfInfo members

    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, AnyOfUdrInfoobject> getServedUdrInfo() const;
    void setServedUdrInfo(std::map<std::string, AnyOfUdrInfoobject> const& value);
    bool servedUdrInfoIsSet() const;
    void unsetServedUdrInfo();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, AnyOfUdrInfoobject>> getServedUdrInfoList() const;
    void setServedUdrInfoList(std::map<std::string, std::map<std::string, AnyOfUdrInfoobject>> const& value);
    bool servedUdrInfoListIsSet() const;
    void unsetServedUdrInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, AnyOfUdmInfoobject> getServedUdmInfo() const;
    void setServedUdmInfo(std::map<std::string, AnyOfUdmInfoobject> const& value);
    bool servedUdmInfoIsSet() const;
    void unsetServedUdmInfo();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, AnyOfUdmInfoobject>> getServedUdmInfoList() const;
    void setServedUdmInfoList(std::map<std::string, std::map<std::string, AnyOfUdmInfoobject>> const& value);
    bool servedUdmInfoListIsSet() const;
    void unsetServedUdmInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, AnyOfAusfInfoobject> getServedAusfInfo() const;
    void setServedAusfInfo(std::map<std::string, AnyOfAusfInfoobject> const& value);
    bool servedAusfInfoIsSet() const;
    void unsetServedAusfInfo();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, AnyOfAusfInfoobject>> getServedAusfInfoList() const;
    void setServedAusfInfoList(std::map<std::string, std::map<std::string, AnyOfAusfInfoobject>> const& value);
    bool servedAusfInfoListIsSet() const;
    void unsetServedAusfInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, AnyOfAmfInfoobject> getServedAmfInfo() const;
    void setServedAmfInfo(std::map<std::string, AnyOfAmfInfoobject> const& value);
    bool servedAmfInfoIsSet() const;
    void unsetServedAmfInfo();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, AnyOfAmfInfoobject>> getServedAmfInfoList() const;
    void setServedAmfInfoList(std::map<std::string, std::map<std::string, AnyOfAmfInfoobject>> const& value);
    bool servedAmfInfoListIsSet() const;
    void unsetServedAmfInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, AnyOfSmfInfoobject> getServedSmfInfo() const;
    void setServedSmfInfo(std::map<std::string, AnyOfSmfInfoobject> const& value);
    bool servedSmfInfoIsSet() const;
    void unsetServedSmfInfo();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, AnyOfSmfInfoobject>> getServedSmfInfoList() const;
    void setServedSmfInfoList(std::map<std::string, std::map<std::string, AnyOfSmfInfoobject>> const& value);
    bool servedSmfInfoListIsSet() const;
    void unsetServedSmfInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, AnyOfUpfInfoobject> getServedUpfInfo() const;
    void setServedUpfInfo(std::map<std::string, AnyOfUpfInfoobject> const& value);
    bool servedUpfInfoIsSet() const;
    void unsetServedUpfInfo();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, AnyOfUpfInfoobject>> getServedUpfInfoList() const;
    void setServedUpfInfoList(std::map<std::string, std::map<std::string, AnyOfUpfInfoobject>> const& value);
    bool servedUpfInfoListIsSet() const;
    void unsetServedUpfInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, AnyOfPcfInfoobject> getServedPcfInfo() const;
    void setServedPcfInfo(std::map<std::string, AnyOfPcfInfoobject> const& value);
    bool servedPcfInfoIsSet() const;
    void unsetServedPcfInfo();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, AnyOfPcfInfoobject>> getServedPcfInfoList() const;
    void setServedPcfInfoList(std::map<std::string, std::map<std::string, AnyOfPcfInfoobject>> const& value);
    bool servedPcfInfoListIsSet() const;
    void unsetServedPcfInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, AnyOfBsfInfoobject> getServedBsfInfo() const;
    void setServedBsfInfo(std::map<std::string, AnyOfBsfInfoobject> const& value);
    bool servedBsfInfoIsSet() const;
    void unsetServedBsfInfo();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, AnyOfBsfInfoobject>> getServedBsfInfoList() const;
    void setServedBsfInfoList(std::map<std::string, std::map<std::string, AnyOfBsfInfoobject>> const& value);
    bool servedBsfInfoListIsSet() const;
    void unsetServedBsfInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, AnyOfChfInfoobject> getServedChfInfo() const;
    void setServedChfInfo(std::map<std::string, AnyOfChfInfoobject> const& value);
    bool servedChfInfoIsSet() const;
    void unsetServedChfInfo();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, AnyOfChfInfoobject>> getServedChfInfoList() const;
    void setServedChfInfoList(std::map<std::string, std::map<std::string, AnyOfChfInfoobject>> const& value);
    bool servedChfInfoListIsSet() const;
    void unsetServedChfInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, AnyOfNefInfoobject> getServedNefInfo() const;
    void setServedNefInfo(std::map<std::string, AnyOfNefInfoobject> const& value);
    bool servedNefInfoIsSet() const;
    void unsetServedNefInfo();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, AnyOfNwdafInfoobject> getServedNwdafInfo() const;
    void setServedNwdafInfo(std::map<std::string, AnyOfNwdafInfoobject> const& value);
    bool servedNwdafInfoIsSet() const;
    void unsetServedNwdafInfo();
    /// <summary>
    /// A map (list of key-value pairs) where NF Instance Id serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, NwdafInfo>> getServedNwdafInfoList() const;
    void setServedNwdafInfoList(std::map<std::string, std::map<std::string, NwdafInfo>> const& value);
    bool servedNwdafInfoListIsSet() const;
    void unsetServedNwdafInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, AnyOfPcscfInfoobject>> getServedPcscfInfoList() const;
    void setServedPcscfInfoList(std::map<std::string, std::map<std::string, AnyOfPcscfInfoobject>> const& value);
    bool servedPcscfInfoListIsSet() const;
    void unsetServedPcscfInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, AnyOfGmlcInfoobject> getServedGmlcInfo() const;
    void setServedGmlcInfo(std::map<std::string, AnyOfGmlcInfoobject> const& value);
    bool servedGmlcInfoIsSet() const;
    void unsetServedGmlcInfo();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, AnyOfLmfInfoobject> getServedLmfInfo() const;
    void setServedLmfInfo(std::map<std::string, AnyOfLmfInfoobject> const& value);
    bool servedLmfInfoIsSet() const;
    void unsetServedLmfInfo();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, NfInfo> getServedNfInfo() const;
    void setServedNfInfo(std::map<std::string, NfInfo> const& value);
    bool servedNfInfoIsSet() const;
    void unsetServedNfInfo();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, AnyOfHssInfoobject>> getServedHssInfoList() const;
    void setServedHssInfoList(std::map<std::string, std::map<std::string, AnyOfHssInfoobject>> const& value);
    bool servedHssInfoListIsSet() const;
    void unsetServedHssInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, AnyOfUdsfInfoobject> getServedUdsfInfo() const;
    void setServedUdsfInfo(std::map<std::string, AnyOfUdsfInfoobject> const& value);
    bool servedUdsfInfoIsSet() const;
    void unsetServedUdsfInfo();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, AnyOfUdsfInfoobject>> getServedUdsfInfoList() const;
    void setServedUdsfInfoList(std::map<std::string, std::map<std::string, AnyOfUdsfInfoobject>> const& value);
    bool servedUdsfInfoListIsSet() const;
    void unsetServedUdsfInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, AnyOfScpInfoobject> getServedScpInfoList() const;
    void setServedScpInfoList(std::map<std::string, AnyOfScpInfoobject> const& value);
    bool servedScpInfoListIsSet() const;
    void unsetServedScpInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, AnyOfSeppInfoobject> getServedSeppInfoList() const;
    void setServedSeppInfoList(std::map<std::string, AnyOfSeppInfoobject> const& value);
    bool servedSeppInfoListIsSet() const;
    void unsetServedSeppInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where NF Instance Id serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, AnyOfAanfInfoobject>> getServedAanfInfoList() const;
    void setServedAanfInfoList(std::map<std::string, std::map<std::string, AnyOfAanfInfoobject>> const& value);
    bool servedAanfInfoListIsSet() const;
    void unsetServedAanfInfoList();
    /// <summary>
    /// 
    /// </summary>
    std::map<std::string, 5GDdnmfInfo> getServed5gDdnmfInfo() const;
    void setServed5gDdnmfInfo(std::map<std::string, 5GDdnmfInfo> const& value);
    bool served5gDdnmfInfoIsSet() const;
    void unsetServed5gDdnmfInfo();
    /// <summary>
    /// A map (list of key-value pairs) where NF Instance Id serves as key
    /// </summary>
    std::map<std::string, MfafInfo> getServedMfafInfoList() const;
    void setServedMfafInfoList(std::map<std::string, MfafInfo> const& value);
    bool servedMfafInfoListIsSet() const;
    void unsetServedMfafInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where NF Instance Id serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, EasdfInfo>> getServedEasdfInfoList() const;
    void setServedEasdfInfoList(std::map<std::string, std::map<std::string, EasdfInfo>> const& value);
    bool servedEasdfInfoListIsSet() const;
    void unsetServedEasdfInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where NF Instance Id serves as key
    /// </summary>
    std::map<std::string, DccfInfo> getServedDccfInfoList() const;
    void setServedDccfInfoList(std::map<std::string, DccfInfo> const& value);
    bool servedDccfInfoListIsSet() const;
    void unsetServedDccfInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where nfInstanceId serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, AnyOfMbSmfInfoobject>> getServedMbSmfInfoList() const;
    void setServedMbSmfInfoList(std::map<std::string, std::map<std::string, AnyOfMbSmfInfoobject>> const& value);
    bool servedMbSmfInfoListIsSet() const;
    void unsetServedMbSmfInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where NF Instance Id serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, TsctsfInfo>> getServedTsctsfInfoList() const;
    void setServedTsctsfInfoList(std::map<std::string, std::map<std::string, TsctsfInfo>> const& value);
    bool servedTsctsfInfoListIsSet() const;
    void unsetServedTsctsfInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where NF Instance Id serves as key
    /// </summary>
    std::map<std::string, std::map<std::string, MbUpfInfo>> getServedMbUpfInfoList() const;
    void setServedMbUpfInfoList(std::map<std::string, std::map<std::string, MbUpfInfo>> const& value);
    bool servedMbUpfInfoListIsSet() const;
    void unsetServedMbUpfInfoList();
    /// <summary>
    /// A map (list of key-value pairs) where NF Instance Id serves as key
    /// </summary>
    std::map<std::string, TrustAfInfo> getServedTrustAfInfo() const;
    void setServedTrustAfInfo(std::map<std::string, TrustAfInfo> const& value);
    bool servedTrustAfInfoIsSet() const;
    void unsetServedTrustAfInfo();

    friend void to_json(nlohmann::json& j, const NrfInfo& o);
    friend void from_json(const nlohmann::json& j, NrfInfo& o);
protected:
    std::map<std::string, AnyOfUdrInfoobject> m_ServedUdrInfo;
    bool m_ServedUdrInfoIsSet;
    std::map<std::string, std::map<std::string, AnyOfUdrInfoobject>> m_ServedUdrInfoList;
    bool m_ServedUdrInfoListIsSet;
    std::map<std::string, AnyOfUdmInfoobject> m_ServedUdmInfo;
    bool m_ServedUdmInfoIsSet;
    std::map<std::string, std::map<std::string, AnyOfUdmInfoobject>> m_ServedUdmInfoList;
    bool m_ServedUdmInfoListIsSet;
    std::map<std::string, AnyOfAusfInfoobject> m_ServedAusfInfo;
    bool m_ServedAusfInfoIsSet;
    std::map<std::string, std::map<std::string, AnyOfAusfInfoobject>> m_ServedAusfInfoList;
    bool m_ServedAusfInfoListIsSet;
    std::map<std::string, AnyOfAmfInfoobject> m_ServedAmfInfo;
    bool m_ServedAmfInfoIsSet;
    std::map<std::string, std::map<std::string, AnyOfAmfInfoobject>> m_ServedAmfInfoList;
    bool m_ServedAmfInfoListIsSet;
    std::map<std::string, AnyOfSmfInfoobject> m_ServedSmfInfo;
    bool m_ServedSmfInfoIsSet;
    std::map<std::string, std::map<std::string, AnyOfSmfInfoobject>> m_ServedSmfInfoList;
    bool m_ServedSmfInfoListIsSet;
    std::map<std::string, AnyOfUpfInfoobject> m_ServedUpfInfo;
    bool m_ServedUpfInfoIsSet;
    std::map<std::string, std::map<std::string, AnyOfUpfInfoobject>> m_ServedUpfInfoList;
    bool m_ServedUpfInfoListIsSet;
    std::map<std::string, AnyOfPcfInfoobject> m_ServedPcfInfo;
    bool m_ServedPcfInfoIsSet;
    std::map<std::string, std::map<std::string, AnyOfPcfInfoobject>> m_ServedPcfInfoList;
    bool m_ServedPcfInfoListIsSet;
    std::map<std::string, AnyOfBsfInfoobject> m_ServedBsfInfo;
    bool m_ServedBsfInfoIsSet;
    std::map<std::string, std::map<std::string, AnyOfBsfInfoobject>> m_ServedBsfInfoList;
    bool m_ServedBsfInfoListIsSet;
    std::map<std::string, AnyOfChfInfoobject> m_ServedChfInfo;
    bool m_ServedChfInfoIsSet;
    std::map<std::string, std::map<std::string, AnyOfChfInfoobject>> m_ServedChfInfoList;
    bool m_ServedChfInfoListIsSet;
    std::map<std::string, AnyOfNefInfoobject> m_ServedNefInfo;
    bool m_ServedNefInfoIsSet;
    std::map<std::string, AnyOfNwdafInfoobject> m_ServedNwdafInfo;
    bool m_ServedNwdafInfoIsSet;
    std::map<std::string, std::map<std::string, NwdafInfo>> m_ServedNwdafInfoList;
    bool m_ServedNwdafInfoListIsSet;
    std::map<std::string, std::map<std::string, AnyOfPcscfInfoobject>> m_ServedPcscfInfoList;
    bool m_ServedPcscfInfoListIsSet;
    std::map<std::string, AnyOfGmlcInfoobject> m_ServedGmlcInfo;
    bool m_ServedGmlcInfoIsSet;
    std::map<std::string, AnyOfLmfInfoobject> m_ServedLmfInfo;
    bool m_ServedLmfInfoIsSet;
    std::map<std::string, NfInfo> m_ServedNfInfo;
    bool m_ServedNfInfoIsSet;
    std::map<std::string, std::map<std::string, AnyOfHssInfoobject>> m_ServedHssInfoList;
    bool m_ServedHssInfoListIsSet;
    std::map<std::string, AnyOfUdsfInfoobject> m_ServedUdsfInfo;
    bool m_ServedUdsfInfoIsSet;
    std::map<std::string, std::map<std::string, AnyOfUdsfInfoobject>> m_ServedUdsfInfoList;
    bool m_ServedUdsfInfoListIsSet;
    std::map<std::string, AnyOfScpInfoobject> m_ServedScpInfoList;
    bool m_ServedScpInfoListIsSet;
    std::map<std::string, AnyOfSeppInfoobject> m_ServedSeppInfoList;
    bool m_ServedSeppInfoListIsSet;
    std::map<std::string, std::map<std::string, AnyOfAanfInfoobject>> m_ServedAanfInfoList;
    bool m_ServedAanfInfoListIsSet;
    std::map<std::string, 5GDdnmfInfo> m_Served5gDdnmfInfo;
    bool m_Served5gDdnmfInfoIsSet;
    std::map<std::string, MfafInfo> m_ServedMfafInfoList;
    bool m_ServedMfafInfoListIsSet;
    std::map<std::string, std::map<std::string, EasdfInfo>> m_ServedEasdfInfoList;
    bool m_ServedEasdfInfoListIsSet;
    std::map<std::string, DccfInfo> m_ServedDccfInfoList;
    bool m_ServedDccfInfoListIsSet;
    std::map<std::string, std::map<std::string, AnyOfMbSmfInfoobject>> m_ServedMbSmfInfoList;
    bool m_ServedMbSmfInfoListIsSet;
    std::map<std::string, std::map<std::string, TsctsfInfo>> m_ServedTsctsfInfoList;
    bool m_ServedTsctsfInfoListIsSet;
    std::map<std::string, std::map<std::string, MbUpfInfo>> m_ServedMbUpfInfoList;
    bool m_ServedMbUpfInfoListIsSet;
    std::map<std::string, TrustAfInfo> m_ServedTrustAfInfo;
    bool m_ServedTrustAfInfoIsSet;
    
};

} // namespace org::openapitools::server::model

#endif /* NrfInfo_H_ */