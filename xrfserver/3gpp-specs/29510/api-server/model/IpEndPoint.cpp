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


#include "IpEndPoint.h"
#include "Helpers.h"

#include <sstream>

namespace org::openapitools::server::model
{

IpEndPoint::IpEndPoint()
{
    m_Ipv4Address = "";
    m_Ipv4AddressIsSet = false;
    m_Ipv6AddressIsSet = false;
    m_TransportIsSet = false;
    m_Port = 0;
    m_PortIsSet = false;
    
}

void IpEndPoint::validate() const
{
    std::stringstream msg;
    if (!validate(msg))
    {
        throw org::openapitools::server::helpers::ValidationException(msg.str());
    }
}

bool IpEndPoint::validate(std::stringstream& msg) const
{
    return validate(msg, "");
}

bool IpEndPoint::validate(std::stringstream& msg, const std::string& pathPrefix) const
{
    bool success = true;
    const std::string _pathPrefix = pathPrefix.empty() ? "IpEndPoint" : pathPrefix;

         
    if (ipv4AddressIsSet())
    {
        const std::string& value = m_Ipv4Address;
        const std::string currentValuePath = _pathPrefix + ".ipv4Address";
                
        

    }
                 
    if (portIsSet())
    {
        const int32_t& value = m_Port;
        const std::string currentValuePath = _pathPrefix + ".port";
                
        
        if (value < 0)
        {
            success = false;
            msg << currentValuePath << ": must be greater than or equal to 0;";
        }
        if (value > 65535)
        {
            success = false;
            msg << currentValuePath << ": must be less than or equal to 65535;";
        }

    }
    
    return success;
}

bool IpEndPoint::operator==(const IpEndPoint& rhs) const
{
    return
    
    
    
    ((!ipv4AddressIsSet() && !rhs.ipv4AddressIsSet()) || (ipv4AddressIsSet() && rhs.ipv4AddressIsSet() && getIpv4Address() == rhs.getIpv4Address())) &&
    
    
    ((!ipv6AddressIsSet() && !rhs.ipv6AddressIsSet()) || (ipv6AddressIsSet() && rhs.ipv6AddressIsSet() && getIpv6Address() == rhs.getIpv6Address())) &&
    
    
    ((!transportIsSet() && !rhs.transportIsSet()) || (transportIsSet() && rhs.transportIsSet() && getTransport() == rhs.getTransport())) &&
    
    
    ((!portIsSet() && !rhs.portIsSet()) || (portIsSet() && rhs.portIsSet() && getPort() == rhs.getPort()))
    
    ;
}

bool IpEndPoint::operator!=(const IpEndPoint& rhs) const
{
    return !(*this == rhs);
}

void to_json(nlohmann::json& j, const IpEndPoint& o)
{
    j = nlohmann::json();
    if(o.ipv4AddressIsSet())
        j["ipv4Address"] = o.m_Ipv4Address;
    if(o.ipv6AddressIsSet())
        j["ipv6Address"] = o.m_Ipv6Address;
    if(o.transportIsSet())
        j["transport"] = o.m_Transport;
    if(o.portIsSet())
        j["port"] = o.m_Port;
    
}

void from_json(const nlohmann::json& j, IpEndPoint& o)
{
    if(j.find("ipv4Address") != j.end())
    {
        j.at("ipv4Address").get_to(o.m_Ipv4Address);
        o.m_Ipv4AddressIsSet = true;
    } 
    if(j.find("ipv6Address") != j.end())
    {
        j.at("ipv6Address").get_to(o.m_Ipv6Address);
        o.m_Ipv6AddressIsSet = true;
    } 
    if(j.find("transport") != j.end())
    {
        j.at("transport").get_to(o.m_Transport);
        o.m_TransportIsSet = true;
    } 
    if(j.find("port") != j.end())
    {
        j.at("port").get_to(o.m_Port);
        o.m_PortIsSet = true;
    } 
    
}

std::string IpEndPoint::getIpv4Address() const
{
    return m_Ipv4Address;
}
void IpEndPoint::setIpv4Address(std::string const& value)
{
    m_Ipv4Address = value;
    m_Ipv4AddressIsSet = true;
}
bool IpEndPoint::ipv4AddressIsSet() const
{
    return m_Ipv4AddressIsSet;
}
void IpEndPoint::unsetIpv4Address()
{
    m_Ipv4AddressIsSet = false;
}
Ipv6Addr IpEndPoint::getIpv6Address() const
{
    return m_Ipv6Address;
}
void IpEndPoint::setIpv6Address(Ipv6Addr const& value)
{
    m_Ipv6Address = value;
    m_Ipv6AddressIsSet = true;
}
bool IpEndPoint::ipv6AddressIsSet() const
{
    return m_Ipv6AddressIsSet;
}
void IpEndPoint::unsetIpv6Address()
{
    m_Ipv6AddressIsSet = false;
}
TransportProtocol IpEndPoint::getTransport() const
{
    return m_Transport;
}
void IpEndPoint::setTransport(TransportProtocol const& value)
{
    m_Transport = value;
    m_TransportIsSet = true;
}
bool IpEndPoint::transportIsSet() const
{
    return m_TransportIsSet;
}
void IpEndPoint::unsetTransport()
{
    m_TransportIsSet = false;
}
int32_t IpEndPoint::getPort() const
{
    return m_Port;
}
void IpEndPoint::setPort(int32_t const value)
{
    m_Port = value;
    m_PortIsSet = true;
}
bool IpEndPoint::portIsSet() const
{
    return m_PortIsSet;
}
void IpEndPoint::unsetPort()
{
    m_PortIsSet = false;
}


} // namespace org::openapitools::server::model

