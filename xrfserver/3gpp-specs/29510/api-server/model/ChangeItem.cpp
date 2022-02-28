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


#include "ChangeItem.h"
#include "Helpers.h"

#include <sstream>

namespace org::openapitools::server::model
{

ChangeItem::ChangeItem()
{
    m_Path = "";
    m_From = "";
    m_FromIsSet = false;
    m_OrigValueIsSet = false;
    m_NewValueIsSet = false;
    
}

void ChangeItem::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::openapitools::server::helpers::ValidationException(msg.str());
    }
}

bool ChangeItem::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool ChangeItem::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "ChangeItem" : pathPrefix;

                        
    return success;
}

bool ChangeItem::operator==(const ChangeItem& rhs) const
{
    return
    
    
    (getOp() == rhs.getOp())
     &&
    
    (getPath() == rhs.getPath())
     &&
    
    
    ((!fromIsSet() && !rhs.fromIsSet()) || (fromIsSet() && rhs.fromIsSet() && getFrom() == rhs.getFrom())) &&
    
    
    ((!origValueIsSet() && !rhs.origValueIsSet()) || (origValueIsSet() && rhs.origValueIsSet() && getOrigValue() == rhs.getOrigValue())) &&
    
    
    ((!newValueIsSet() && !rhs.newValueIsSet()) || (newValueIsSet() && rhs.newValueIsSet() && getNewValue() == rhs.getNewValue()))
    
    ;
}

bool ChangeItem::operator!=(const ChangeItem& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const ChangeItem& o)
{
    j = nlohmann::json();
    j["op"] = o.m_Op;
    j["path"] = o.m_Path;
    if(o.fromIsSet())
        j["from"] = o.m_From;
    if(o.origValueIsSet())
        j["origValue"] = o.m_OrigValue;
    if(o.newValueIsSet())
        j["newValue"] = o.m_NewValue;
    
}

void from_json(const nlohmann::json& j, ChangeItem& o)
{
    j.at("op").get_to(o.m_Op);
    j.at("path").get_to(o.m_Path);
    if(j.find("from") != j.end())
    {
        j.at("from").get_to(o.m_From);
        o.m_FromIsSet = true;
    } 
    if(j.find("origValue") != j.end())
    {
        j.at("origValue").get_to(o.m_OrigValue);
        o.m_OrigValueIsSet = true;
    } 
    if(j.find("newValue") != j.end())
    {
        j.at("newValue").get_to(o.m_NewValue);
        o.m_NewValueIsSet = true;
    } 
    
}

ChangeType ChangeItem::getOp() const
{
    return m_Op;
}
void ChangeItem::setOp(ChangeType const& value)
{
    m_Op = value;
}
std::string ChangeItem::getPath() const
{
    return m_Path;
}
void ChangeItem::setPath(std::string const& value)
{
    m_Path = value;
}
std::string ChangeItem::getFrom() const
{
    return m_From;
}
void ChangeItem::setFrom(std::string const& value)
{
    m_From = value;
    m_FromIsSet = true;
}
bool ChangeItem::fromIsSet() const
{
    return m_FromIsSet;
}
void ChangeItem::unsetFrom()
{
    m_FromIsSet = false;
}
AnyType ChangeItem::getOrigValue() const
{
    return m_OrigValue;
}
void ChangeItem::setOrigValue(AnyType const& value)
{
    m_OrigValue = value;
    m_OrigValueIsSet = true;
}
bool ChangeItem::origValueIsSet() const
{
    return m_OrigValueIsSet;
}
void ChangeItem::unsetOrigValue()
{
    m_OrigValueIsSet = false;
}
AnyType ChangeItem::getNewValue() const
{
    return m_NewValue;
}
void ChangeItem::setNewValue(AnyType const& value)
{
    m_NewValue = value;
    m_NewValueIsSet = true;
}
bool ChangeItem::newValueIsSet() const
{
    return m_NewValueIsSet;
}
void ChangeItem::unsetNewValue()
{
    m_NewValueIsSet = false;
}


} // namespace org::openapitools::server::model

