#ifndef FILE_PROFILE_SEEN
#define FILE_PROFILE_SEEN

#include <vector>
#include <stdint.h>
#include <string>

typedef struct ip_endpoint_s {

	struct in_addr ipv4_address;
	std::string transport;
	unsigned int port;
	std::string to_string() const {
		std::string s = {};
		s.append("Ipv4 Address: ");
		s.append(inet_ntoa(ipv4_address));
		s.append(", TransportProtocol: ");
		s.append(transport);
		s.append(", Port: ");
		s.append(std::to_string(port));
		return s;
	}
} ip_endpoint_t;

typedef struct xapp_func_s {

	std::string service_instance_id;
	std::string service_name;
	std::string nf_service_status;
	std::vector<ip_endpoint_t> ip_endpoints;

	std::string to_string() const {
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
} xapp_func_t;

#endif
