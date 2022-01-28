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
//#include <AccessTokenResponse.h> TODO implement in the api-server a seperate section for the response that will be sent upon an acces token request 
//#include "genuint.hpp" TODO a header for generating unsigned integers for different types using templates 
#include "ProblemDetails.h"
#include "xrf_action.hpp"
#include "xrf_profile.hpp"
#include "xrf_search.hpp"
#include "xrf_subscribe.hpp"

namespace xrf {
namespace app {

using namespace::xrf::app;
class xrf_config;
class xrf_main{
	public:
		xrf_main(const std::string& configuration, xrf_action& action);
		xrf_main(xrf_main const&) = delete;
		void operator = (xrf_main const&) = delete;
		
		void generator_uuid();
		/*
		 * Generate a unique string for the XRF ID 
		 */

		void register_xapp(const std::string& xapp_id, int& http_n, const uint8_t http_v, ProblemDetails& problem_details);
		/*
		 * Carry out xApp registration
		 * @param {xapp_id}: xApp instance ID
		 * @param {http_n}: http message code
		 * @param {http_v}: http version --> 1.1
		 * @param {problem_details}: auto-generated api parameter describing error cases
		 */

                void dregister_xapp(const std::string& xapp_id, int& http_n, const uint8_t http_v, ProblemDetails& problem_details);
                /*
                 * Carry out xApp de-registration
                 * @param {xapp_id}: xApp instance ID
                 * @param {http_n}: http message code
                 * @param {http_v}: http version --> 1.1
                 * @param {problem_details}: auto-generated api parameter describing error cases
                 */

		void xapp_fetch(const std::string& xapp_id, const std::vector<std::string>& xapp_uris, int& http_n, const uint8_t http_v, ProblemDetails& problem_details);
		/*
		 * @param {xapp_id}: xApp instance ID
		 * @param {xapp_uris}: current list xApps registered
		 * @param {http_n}: http message code
		 * @oaram {http_v}: http version --> 1.1
		 * @param {problem_details}: auto-generated api parameter describing error cases
		 */



	private:







}




}
}





#endif
