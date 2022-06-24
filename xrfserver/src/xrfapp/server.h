/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 *
 * Fundamental struct(s) for xrf server side
 *
 * ! file server.h
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#ifndef FILE_SERVER_SEEN
#define FILE_SERVER_SEEN

#include <vector>
#include <netinet/in.h>
#include <arpa/inet.h>


typedef struct s_ip_end {
  struct in_addr ipv4_address;
  std::string transport;
  unsigned int port;
  std::string create_string() const {
    std::string s = {};
    s.append("Ipv4 Address: ");
    s.append(inet_ntoa(ipv4_address));
    s.append(", TransportProtocol: ");
    s.append(transport);
    s.append(", Port: ");
    s.append(std::to_string(port));
    return s;
  }
} t_ip_end;

typedef struct s_instance_service {
  std::string service_instance_id;
  std::string service_name;
  std::string nf_service_status;
  std::vector<t_ip_end> ip_endpoints;

  std::string create_string() const {
    std::string s = {};
    s.append("Service Instance ID: ");
    s.append(service_instance_id);
    s.append(", Service name: ");
    s.append(service_name);
    s.append(", Service status: ");
    s.append(nf_service_status);
    s.append(",  IpEndPoints: ");
    for (auto endpoint : ip_endpoints) {
      s.append(endpoint.to_string());
    }
    return s;
  }
} t_instance_service;

#endif
