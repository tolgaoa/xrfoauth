/*
 * Client side of the xApp authorization framework to be integrated into the reference RAN Intelligent 
 * Controller (RIC) of the Linux Foundation (LF) for distributing access tokens to xApps from an 
 * OAUTH 2.0 server using JSON web tokens as the execution method of the tokens
 *
 *
 * ! file xrfclient_profile.hpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#ifndef FILE_XAPPCLIENT_PROFILE_SEEN
#define FILE_XAPPCLIENT_PROFILE_SEEN

#include <arpa/inet.h>
#include <netinet/in.h>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <shared_mutex>
#include <utility>
#include <vector>

#include "logger.hpp"

namespace xappclient {

class xappclient_profile : public std::enable_shared_from_this<xappclient_profile> {
	public:
		xappclient_profile(const std::string& id) : 
			xappclient_instance_id(id),
			ipv4_addresses() {
			
				xappclient_instance_name = "";
				xappclient_status = "";
			}
		xappclient_profile& operator=(const xappclient_profile& x) {
			xappclient_instance_id = x.xappclient_instance_id;
			ipv4_addresses = x.ipv4_addresses;
			xappclient_instance_name = x.xappclient_instance_name;
			xappclient_status = x.xappclient_status;
			return *this;
		}

		void set_xappclient_instance_id(const std::string& instance_id); 
		/*
		 * set instance id for an xapp instance
		 * @param instance_id 
		 */

		std::string get_xappclient_instance_id() const;
		/*
		 * retreive the id of an xapp instance
		 */

		void set_xappclient_instance_name(const std::string& instance_name);
		/*
		 * set the instance name for an xapp instance
		 * @param instance name
		 */

		std::string get_xappclient_instance_name() const;
		/* 
		 * retreive the name of an xapp instance
		 */

		void set_xappclient_status(const std::string& instance_status);
		/*
		 * set the status of an xapp instance
		 * @param instance status
		 */

		std::string get_xappclient_status() const;
		/*
		 * retrieve the status of an xapp instance
		 */

		void set_xappclient_ipv4(const std::vector<struct in_addr>& addresses);
		/*
		 * set the ipv4 addresses for the xapp instance
		 * @param addresses: set of addresses
		 */

		void display() const;
		/*
		 * display the xapp information
		 */

		std::string xappclient_instance_id;
		std::string xappclient_instance_name;
		std::string xappclient_status;
		std::vector<struct in_addr> ipv4_addresses;
	     	       
};


}

#endif 
