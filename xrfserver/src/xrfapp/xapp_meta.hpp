/*
 * Client side of the xApp authorization framework to be integrated into the reference RAN Intelligent 
 * Controller (RIC) of the Linux Foundation (LF) for distributing access tokens to xApps from an 
 * OAUTH 2.0 server using JSON web tokens as the execution method of the tokens
 *
 * Store xApp metadata
 *
 * ! file xapp_meta.hpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#ifndef FILE_XAPP_META_SEEN
#define FILE_XAPP_META_SEEN

#include <unordered_map>
#include <iostream>

#include "spdlog/spdlog.h"

typedef struct xapp_profile_s {
	std::string xapp_instance_id;
	std::string xapp_instance_name;
	std::string xapp_instance_func;
 	std::string xapp_instance_status;
	std::string ipv4_addresses;
	std::string xapp_instance_loc;
	int xapp_clients;
	std::vector<std::string> servers;
	std::vector<std::string> consumers;

	std::string to_string() const {
		std::string s = {};
		s.append("xApp Id: ");
		s.append(xapp_instance_id);
		s.append(", xApp Name: ");
		s.append(xapp_instance_name);
		s.append(", xApp Function: ");
		s.append(xapp_instance_func);
		s.append(", xApp Status: ");
		s.append(xapp_instance_status);
		s.append(", xApp Ipv4: ");
		s.append(ipv4_addresses);
                s.append(", xApp Location: ");
                s.append(xapp_instance_loc);
                s.append(", xApp Clients: ");
                s.append(std::to_string(xapp_clients));
		/*s.append("xApp Location: ");
                s.append(xapp_instance_loc);
                s.append("xApp Location: ");
                s.append(xapp_instance_loc);
                s.append("xApp Location: ");
                s.append(xapp_instance_loc);
		*/
		return s;
	}

} xapp_profile_t;


namespace xrf {
namespace app {

class xapp_meta {

	public:
		xapp_meta();
		//xapp_meta(xapp_meta const&) = delete;
		virtual ~ xapp_meta();
		//void operator=(xapp_meta const&) = delete;

		void register_profile(std::vector<std::string>& data, std::string& key, std::string& map, std::unordered_map<std::string, xapp_profile_t>& xapp_map);
		/*
		 * Register xApp into unordered_map
		 * @param[data] : vector string values for xApp data
		 * @param[key] : key for unordered_map
		 * @param[map] : which map to update
		 * @param[xpp_map] : map itself
		 * return void
		 */

		void update_profile(std::string& key_id, std::unordered_map<std::string, xapp_profile_t>& xapp_map_i, std::unordered_map<std::string, xapp_profile_t>& xapp_map_f, xapp_profile_t xapp_profile);
		/*
		 * Update existing profile
		 * @param[instance_id key] : instance id of profile to update
		 * @param[xapp_map_i] : map for xid and profile 
		 * @param[xapp_map_f] : map for xfunc and profile 
		 * return void
		 */

		void delete_profile(std::string& key_id, std::unordered_map<std::string, xapp_profile_t>& xapp_map_i, std::unordered_map<std::string, xapp_profile_t>& xapp_map_f);
		/* 
		 * delete existing profile
		 * @param[key_id] : instance id of profile to delete
		 * @param[xapp_map_i] : map for xid and profile 
		 * @param[xapp_map_f] : map for xfunc and profile 
		 * return void
		 */

		void display_map(std::unordered_map<std::string, xapp_profile_t>& xapp_map);
		/* 
		 * display contents of xapp profile map
		 * @param[xapp_map] : unordered_map containing xapp_profiles
		 * return void
		 */
	private: 
		std::unordered_map<std::string, xapp_profile_t*> xapp_i_p;
		std::unordered_map<std::string, xapp_profile_t*> xapp_f_p;

};

} // namespace app
} // namespace xrf

#endif

