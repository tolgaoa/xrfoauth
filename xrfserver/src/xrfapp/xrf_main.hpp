/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 *
 *
 * ! file xrf_main.hpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#ifndef FILE_XRF_MAIN_HPP_SEEN
#define FILE_XRF_MAIN_HPP_SEEN


#include <curl/curl.h>

#include <string>
#include <iostream>
#include "ProblemDetails.h"
#include "AccessTokenRsp.h"
#include "InitAuthRsp.h"

#include "spdlog/spdlog.h"

#include "xrf_msg.hpp"
#include "xrf_jwt.hpp"
#include "xapp_meta.hpp"

namespace xrf {
namespace app {

using namespace::xrf::model;
class xrf_main{
	public:
		//xrf_main(const std::string& configuration, xrf_action& action);
		xrf_main(xrf_main const&) = delete;
		void operator = (xrf_main const&) = delete;
		
		void generator_uuid();
		/*
		 * Generate a unique string for the XRF ID 
		 */

		void register_xapp(const std::string& xapp_id, int& http_n, const uint8_t http_v, 
				   ProblemDetails& problem_details);
		/*
		 * Carry out xApp registration
		 * @param {xapp_id}: xApp instance ID
		 * @param {http_n}: http message code
		 * @param {http_v}: http version --> 1.1
		 * @param {problem_details}: auto-generated api parameter describing error cases
		 */

                void dregister_xapp(const std::string& xapp_id, int& http_n, const uint8_t http_v, 
				    ProblemDetails& problem_details);
                /*
                 * Carry out xApp de-registration
                 * @param {xapp_id}: xApp instance ID
                 * @param {http_n}: http message code
                 * @param {http_v}: http version --> 1.1
                 * @param {problem_details}: auto-generated api parameter describing error cases
                 */

		void xapp_fetch(const std::string& xapp_id, const std::vector<std::string>& xapp_uris, 
				int& http_n, const uint8_t http_v, ProblemDetails& problem_details);
		/*
		 * @param {xapp_id}: xApp instance ID
		 * @param {xapp_uris}: current list xApps registered
		 * @param {http_n}: http message code
		 * @oaram {http_v}: http version --> 1.1
		 * @param {problem_details}: auto-generated api parameter describing error cases
		 */

		 void access_token_request(const std::string& request_main, AccessTokenRsp& ac_tok_rsp, int& http_code, const uint8_t http_version, ProblemDetails& problem_details);
		 /*
		  * @param{request_main}: the main body which includes the request for the token
		  * @param{ac_tok_rsp}: the response
		  * @param{http_code}: http message code
		  * @param{http_version}: http version --> 1
		  * @param{problem_details}: auto generated api parameter describing error cases
		  */

		 void handle_auth_request(const std::string& request_main, InitAuthRsp& in_auth_rsp, int& http_code, const uint8_t http_version, ProblemDetails& problem_details);
		 /*
		  * @param{request_main}: the main body which includes the initial information received from te client side
		  * @param{in_auth_rsp}: the response
		  * @param{http_code}: http message code
		  * @param{http_version}: http version --> 1
		  * @param{problem_details}: auto generated api parameter describing error cases
		  */

		void handle_reg_request(const std::string& request_main, int& http_code, const uint8_t http_version, ProblemDetails& problem_details);
		/*
		 * Handle xApp registration request
		 * @param{request_main} : contains xApp profile
		 * @param{httpcode}
		 * @param{http_version}
		 * @param{problem_details}
		*/

		void handle_search_xapp_instances(const std::string& targetxApp, 
				const std::string& targetLoc, 
				std::vector<std::string>& search_result,
				int& http_code, const uint8_t http_version,
				ProblemDetails& problem_details);
		/*
		 * Handle xApp discovery request
		 * @param[targetxApp] : query for target xApp function
		 * @param[targetLoc] : query for target xApp location
		 * @param[limit_nfs] : maximum number of resulsts to return
		 * @param[search_result] : store search result ID
		 * @param[http_code] : http code to return
		 * @param[http_versoin] : http version ued
		 * @param[problem_details] : error details
		 */

		void fetch_token_key(std::string& kid, std::string& token_pub_key);
		/*
		 * get public key corresponding to a key id
		 * @param[kid] : key id
		 * @param[token_pub_key] : public key for the token
		 * return void
		 */

		void validate_token(const std::string& token, bool& validity);
		/*
		 * validate token for introspection endpoint
		 * @param[token] : token reqeust coming from client
		 * @param[validity] : valid or not
		 * return void
		 */

		void vector_to_json(std::vector<std::string>& vector_ids, nlohmann::json& json_data);
		/*
		 * convert vector of xapp ids to json
		 * @param[json_data] : json to feedback
		 * @param[vector_ids] : vector of ids received
		 * return void
		 */

		void check_client_clount(int& clientc);
		/*
		 * check client count for throughput calculation
		 * @param[clientc] : client count
		 * return void
		 */

};

}
}

#endif
