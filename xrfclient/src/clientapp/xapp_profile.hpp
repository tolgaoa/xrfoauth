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
#include <string>

#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // generators
#include <boost/uuid/uuid_io.hpp>	  // streaming operators etc.

#include "spdlog/spdlog.h"

namespace xrf {
namespace app {

using namespace std;

class xapp_profile {
	public:
		xapp_profile(std::string id, std::string name, std::string status, std::string func, std::string addresses, std::string loc, int clients)
		{
			xapp_instance_id = id;
			xapp_instance_name = name;
			xapp_instance_status = status;
			xapp_instance_func = func;
			xapp_instance_loc = loc;
			ipv4_addresses = addresses;
			xapp_clients = clients;

		}
		virtual ~xapp_profile () {}

		void set_instance_id(std::string instance_id); 
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

		void set_instance_name(std::string instance_name);
		/*
		 * set the instance name for an xapp instance
		 * @param instance name
		 */

		std::string get_instance_name();
		/* 
		 * retreive the name of an xapp instance
		 */

		void set_status(std::string instance_status);
		/*
		 * set the status of an xapp instance
		 * @param instance status
		 */

		std::string get_status();
		/*
		 * retrieve the status of an xapp instance
		 */

		void set_func(std::string instance_func);
		/*
		 * set the function of an xapp instance
		 * @param instance function
		 */

		std::string get_func();
		/*
		 * get the function of an xapp instance
		 */

		void set_ipv4(std::string addresses);
		/*
		 * set the ipv4 addresses for the xapp instance
		 * @param addresses: set of addresses
		 */

		void create_profile(std::string instance_id_v, std::string instance_name_v,
                                  std::string instance_status_v, std::string func_v,
                                  std::string addresses);
		/*
		 * @param : all class variables
		 * create profile from scratch 
		 */

		void profile_to_json(nlohmann::json& data);
		/*
		* turn xapp profile to json
		* @param data: Json data
		* @return void
		*/

                void profile_to_vector_s(std::vector<std::string>& data);
                /*
                * turn xapp profile to string vector
                * @param data: string vector
                * @return void
                */
		
		void display();
		/*
		 * display the xapp information
		 */
		
	private:
		std::string xapp_instance_id;
		std::string xapp_instance_name;
		std::string xapp_instance_status;
		std::string xapp_instance_func;
		std::string xapp_instance_loc;
		std::string ipv4_addresses;
		int xapp_clients;
		nlohmann::json custom_info;
};

} // namespace app
} // namespace xrf

#endif 
