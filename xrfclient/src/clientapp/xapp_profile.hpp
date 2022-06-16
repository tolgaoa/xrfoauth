/*
 * Client side of the xApp authorization framework to be integrated into the reference RAN Intelligent 
 * Controller (RIC) of the Linux Foundation (LF) for distributing access tokens to xApps from an 
 * OAUTH 2.0 server using JSON web tokens as the execution method of the tokens
 *
 *
 * ! file xapp_profile.hpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#ifndef FILE_XAPP_PROFILE_SEEN
#define FILE_XAPP_PROFILE_SEEN

#include <arpa/inet.h>
#include <netinet/in.h>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <shared_mutex>
#include <utility>
#include <vector>
#include <iostream>

#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // generators
#include <boost/uuid/uuid_io.hpp>	  // streaming operators etc.

#include "profile.h"
#include "spdlog/spdlog.h"

namespace xrf {
namespace app {

using namespace std;

class xapp_profile {
	public:
                explicit xapp_profile();
                xapp_profile(xapp_profile const&) = delete;
                virtual ~xapp_profile();

		void set_instance_id(std::string& instance_id_v); 
		/*
		 * set instance id for an xapp instance manually
		 * @param instance_id 
		 */

		void create_instance_id();
		/*
		 * set instance id from random uuid
		 */

		std::string get_instance_id();
		/*
		 * retreive the id of an xapp instance
		 */

		void set_instance_name(std::string& instance_name_v);
		/*
		 * set the instance name for an xapp instance
		 * @param instance name
		 */

		std::string get_instance_name();
		/* 
		 * retreive the name of an xapp instance
		 */

		void set_status(std::string& instance_status_v);
		/*
		 * set the status of an xapp instance
		 * @param instance status
		 */

		std::string get_status();
		/*
		 * retrieve the status of an xapp instance
		 */

		void set_func(std::string& func_v);
		/*
		 * set the function of an xapp instance
		 * @param instance function
		 */

		std::string get_func();
		/*
		 * get the function of an xapp instance
		 */

		void set_ipv4(std::vector<std::string>& addresses);
		/*
		 * set the ipv4 addresses for the xapp instance
		 * @param addresses: set of addresses
		 */

		void create_profile(std::string& instance_id_v, std::string& instance_name_v,
                                  std::string& instance_status_v, std::string& func_v,
                                  std::vector<std::string>& addresses);

		void display();
		/*
		 * display the xapp information
		 */
		
		void create_uuid();
		/*
		 * randomize uuid for instance_id calling
		 */

		std::string instance_id;
		std::string instance_name;
		std::string status;
		std::string func;
		std::vector<string> ipv4_addresses;
	     	       
};

} // namespace app
} // namespace xrf

#endif 
