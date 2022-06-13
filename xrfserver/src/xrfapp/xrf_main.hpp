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


#include <string>
#include "ProblemDetails.h"
#include "AccessTokenRsp.h"
#include "InitAuthRsp.h"

#include "spdlog/spdlog.h"

#include "xrf_rec_msg.hpp"
#include "xrf_jwt.hpp"
//#include "xrf_profile.hpp"

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


	private:
		 /*std::string xrf_id;
		 std::map<std::string, std::shared_ptr<xrf_profile>> instance_id_to_xrf_profile;
		 std::shared_mutex mut_instance_id_conv_xrf_profile;

  		 std::map<std::string, std::shared_ptr<xrf_subscription>>subscrition_id_conv_xrf_subscription;
                 mutable std::shared_mutex mut_subscription_id_conv_xrf_subscription;
                 xrf_event& m_event_sub;
                 util::uint_generator<uint32_t> evsub_id_generator;
                 std::vector<bs2::connection> connections;

                 util::uint_generator<uint32_t> search_id_generator;
                 std::map<std::string, std::shared_ptr<xrf_search_result>>search_id_conv_search_result;
                 mutable std::shared_mutex mut_search_id_conv_search_result;*/

};

}
}

#endif
