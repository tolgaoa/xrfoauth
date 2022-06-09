/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 *
 * XRF client for sending out CURL commands
 *
 * ! file xrf_client.hpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/


#ifndef FILE_XRF_CLIENT_HPP_SEEN
#define FILE_XRF_CLIENT_HPP_SEEN

#include <thread>
#include <curl/curl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <shared_mutex>
#include <utility>
#include <vector>

#include "spdlog/spdlog.h"
#include "string.hpp"

namespace xrf {
namespace app {

class xrf_client {
	private:
		CURLM* curl_multi;
		std::vector<CURL*> handles;
		struct curl_slist* headers;
	
	public: 
		xrf_client();
		virtual ~xrf_client();

		xrf_client(xrf_client const&) = delete;
		void operator=(xrf_client const &) = delete;


		CURL* curl_create_handle(const std::string& uri, const std::string& data,
					 std::string& response_data, uint8_t http_version);
		/*
		 * @param[uri] : URI
		 * @param[data] : data to send
		 * @param[response_data] : response to the data
		 * @return void
		 */

		void send_curl_multi(const std::string& uri, const std::string& data, 
				     std::string& response_data, uint8_t http_version);
		/*
		 * @param[uri] : URI
		 * @param[data] : data to send
		 * @param[response_data] : response to the data
		 * return void
		 */

		void perform_curl_multi();
		/*
		 * Carry out the curl multi to process the data
		 * return void
		 */

		void wait_curl_end();
		/*
		 * Finish the curl transfers
		 * @param void
		 * @return void
		 */

		void curl_release_handles();
		/*
		 * Release curl handles
		 * @param void
		 * @return void
		 */
	
};


} // namespace app
} // namespace xrf



#endif 
