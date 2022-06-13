/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 *
 * Create and manage xrf_profile as well as the xApp profiles that are included in it
 *
 * ! file xrf_profile.hpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#ifndef FILE_XRF_PROFILE_HPP_SEEN
#define FILE_XRF_PROFILE_HPP_SEEN

#include <arpa/inet.h>
#include <netinet/in.h>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <shared_mutex>
#include <utility>
#include <vector>

#include "spdlog/spdlog.h"
#include "server.h"
#include "xrf.h"

namespace xrf {
namespace app {

using namespace std;

class xrf_profile : public std::enable_shared_from_this<xrf_profile> {
	public:
		xrf_profile(std::string& id) : 
			ipv4_addresses(),
			capacity(0),
			xapp_services();
		}
		virtual ~xrf_profile();
                xrf_profile(xrf_profile const&) = delete;
                void operator=(xrf_profile const &) = delete;
		
		void set_xrf_instance_id(const std::string& xapp_id);
		/*
		 * Set instance id
		 * @param[xapp_id] choose and id for xapp
		 * return void
		 */

		std::string get_xrf_instance_id(const std::string& xapp_id) const;
		/*
		 * Get instance id
		 * return string
		 */

		void set_xrf_name(const std::string& instance_name);
		/*
		* Set instance name
		* @param[instance_name] store instance name
		* @return void
		*/
		
		std::string get_xrf_name() const;
		/*
		* Get instance name
		* @return string
		*/

		t_type get_instance_type() const;
		/*
		* Get instance type
		* @return t_type
		*/

		void set_instance_type(const t_type& type);
		/*
		* Set instance type
		* @param[t_type] : type
		* @return void
		*/

		void set_ipv4_addresses(const std::vector<struct in_addr>& addr);
		/*
		* Set instance ipv4_addresses
		* @param [addr] ipv4_addresses
		* @return void
		*/

		void set_instance_capacity(const uint16_t& c);
		/*
		* Set instance capacity
		* @param [c] : instance capacity
		* @return void
		*/

		uint16_t get_instance_capacity() const;
		/*
		* Get instance priority
		* @param void
		* @return uint16_t 
		*/

		void set_jdata(const nlohmann::json& data);
		/*
		* Set json data
		* @param [data] : Json data to be set
		* @return void
		*/

		nlohmann::json get_jdata() const;
		/*
		* Get json data
		* @return nlohmann::json
		*/

		void set_instance_services(const std::vector<t_instance_service>& s);
		/*
		* Set NF instance services
		* @param [s] : instance_service
		* @return void
		*/

		void add_instance_service(const t_instance_service& s);
		/*
		* Add nf service
		* @param [s] : instance service
		* @return void
		*/

		std::vector<t_instance_service> get_instance_services() const;
		/*
		* Get NF services
		* @return std::vector<t_instance_service>:
		*/

		virtual void display();
		/*
		* Print all instance info
		* @return void:
		*/


	protected:
		bool is_updated;
		std::string instance_id;
		std::string instance_name;
		std::string instance_type;
		std::vector<struct in_addr> ipv4_addresses;
		uint16_t capacity;
		nlohmann::json json_data;
		std::vector<t_instance_service> instance_services;

	
};


}
}

#endif

