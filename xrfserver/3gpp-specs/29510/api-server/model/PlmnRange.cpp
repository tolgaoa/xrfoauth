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


#include "PlmnRange.h"
#include "Helpers.h"

#include <sstream>

namespace org::openapitools::server::model
{

PlmnRange::PlmnRange()
{
    m_Start = "";
    m_StartIsSet = false;
    m_End = "";
    m_EndIsSet = false;
    m_Pattern = "";
    m_PatternIsSet = false;
    
}

void PlmnRange::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::openapitools::server::helpers::ValidationException(msg.str());
    }
}

bool PlmnRange::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool PlmnRange::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "PlmnRange" : pathPrefix;

         
    if (startIsSet())
    {
        const std::string& value = m_Start;
        const std::string currentValuePath = _pathPrefix + ".start";
                
        

    }
         
    if (endIsSet())
    {
        const std::string& value = m_End;
        const std::string currentValuePath = _pathPrefix + ".end";
                
        

    }
        
    return success;
}

bool PlmnRange::operator==(const PlmnRange& rhs) const
{
    return
    
    
    
    ((!startIsSet() && !rhs.startIsSet()) || (startIsSet() && rhs.startIsSet() && getStart() == rhs.getStart())) &&
    
    
    ((!endIsSet() && !rhs.endIsSet()) || (endIsSet() && rhs.endIsSet() && getEnd() == rhs.getEnd())) &&
    
    
    ((!patternIsSet() && !rhs.patternIsSet()) || (patternIsSet() && rhs.patternIsSet() && getPattern() == rhs.getPattern()))
    
    ;
}

bool PlmnRange::operator!=(const PlmnRange& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const PlmnRange& o)
{
    j = nlohmann::json();
    if(o.startIsSet())
        j["start"] = o.m_Start;
    if(o.endIsSet())
        j["end"] = o.m_End;
    if(o.patternIsSet())
        j["pattern"] = o.m_Pattern;
    
}

void from_json(const nlohmann::json& j, PlmnRange& o)
{
    if(j.find("start") != j.end())
    {
        j.at("start").get_to(o.m_Start);
        o.m_StartIsSet = true;
    } 
    if(j.find("end") != j.end())
    {
        j.at("end").get_to(o.m_End);
        o.m_EndIsSet = true;
    } 
    if(j.find("pattern") != j.end())
    {
        j.at("pattern").get_to(o.m_Pattern);
        o.m_PatternIsSet = true;
    } 
    
}

std::string PlmnRange::getStart() const
{
    return m_Start;
}
void PlmnRange::setStart(std::string const& value)
{
    m_Start = value;
    m_StartIsSet = true;
}
bool PlmnRange::startIsSet() const
{
    return m_StartIsSet;
}
void PlmnRange::unsetStart()
{
    m_StartIsSet = false;
}
std::string PlmnRange::getEnd() const
{
    return m_End;
}
void PlmnRange::setEnd(std::string const& value)
{
    m_End = value;
    m_EndIsSet = true;
}
bool PlmnRange::endIsSet() const
{
    return m_EndIsSet;
}
void PlmnRange::unsetEnd()
{
    m_EndIsSet = false;
}
std::string PlmnRange::getPattern() const
{
    return m_Pattern;
}
void PlmnRange::setPattern(std::string const& value)
{
    m_Pattern = value;
    m_PatternIsSet = true;
}
bool PlmnRange::patternIsSet() const
{
    return m_PatternIsSet;
}
void PlmnRange::unsetPattern()
{
    m_PatternIsSet = false;
}


} // namespace org::openapitools::server::model

