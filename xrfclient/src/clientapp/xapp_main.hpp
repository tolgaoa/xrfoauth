/*
 * Client side of the xApp authorization framework to be integrated into the reference RAN Intelligent 
 * Controller (RIC) of the Linux Foundation (LF) for distributing access tokens to xApps from an 
 * OAUTH 2.0 server using JSON web tokens as the execution method of the tokens
 *
 *
 * ! file xappclient_main.hpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#ifndef FILE_XAPPCLIENT_MAIN_HPP_SEEN
#define FILE_XAPPCLIENT_MAIN_HPP_SEEN

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/thread/future.hpp>
#include <future>
#include <map>
#include <set>
#include <shared_mutex>
#include <string>
#include <thread>

#include <sstream>
#include <iomanip>

#include "xrf_client.hpp"
#include "xapp_msg.hpp"
#include "xapp_profile.hpp"
#include "spdlog/spdlog.h"
#include "xapp_jwt.hpp"
#include "keys.hpp"


namespace xrf {
namespace app {

class xapp_main {

	public:
		explicit xapp_main();
		xapp_main(xapp_main const&) = delete;
		virtual ~xapp_main();

		void operator=(xapp_main const&) = delete;
		
		void sendauth_to_xrf(const std::string& challenge, const std::string& xrfaddress);
		/*
		 * @param[challenge] : challenge sent to 
		 * @param[xrfaddress] : full address path and port for XRF
		 * return void
		 */
				
		void register_with_xrf(const std::string& xrfaddress);
		/*
		 * Register the xapp with the XRF server
		 */

		void send_discovery_request(std::string& xrfaddressbase, const std::string& targetxApp, const std::string& targetLoc);
		/*
		 * @param[xrfaddressbase] : base address of xrf without queries
		 * @param[targetxApp] : targetxApp query
		 * @param[targetLoc] : targetLoc query
		 * @param[disc_map] : discovery result
		 */
		
		std::string& create_auth_challenge();
                /*
                 * Create authentication challenge for XRF
                 */

		void send_xapp_registration_request();
		/*
		 * initate a request to the XRF for registration
		 */

                void generate_profile(std::string instance_id_v, std::string instance_name_v,
                                      std::string instance_status_v, std::string func_v,
                                      std::string addresses, std::string loc_v, int cap);
		/*
		 * create xapp profile by invoking setters and creators
		 */

		void send_token_req(const std::string& xrfaddress);
		/*
		 * send access token request
		 * @param[xrfaddress] : target endpoint on xrfserver
		 * return void
		 */

		void validate_token_self(const std::string& xrfaddress, std::string& token, bool& validity);
		/*
		 * call internal validation
		 * @param[xrfaddress] : address of the jwks endpoint on server
		 * @param[token] : JWT
		 * @param[validity] token validity
		 * return true
		 */

                void validate_token_remote(const std::string& xrfaddress, std::string& token, bool& validity);
                /*
                 * call remote validation
		 * @param[xrfaddress] : address of the introspection endpoint on server
                 * @param[token] : JWT
		 * @param[validity] : token validity
                 * return true
                 */
	
		void display_profile();
		/*
		 * display xapp profile
		 */

		void send_client_connection(const std::string& xrfcaddress);
		/*
		 * send client connection
		 * @param[xrfcaddress] : address of the client server
		 * @param[token] : token to use
		 */

        private:
                std::string xappclient_instance_id;
		xapp_profile xapp_instance_profile;
};


}
}


#endif
