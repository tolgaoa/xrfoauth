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
#include <cmath>
#include <vector>

#include <unistd.h>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/date_time/posix_time/time_formatters.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>


#include "spdlog/spdlog.h"
#include <string>
#include <iostream>

#include <nlohmann/json.hpp>


typedef struct xapp_profile_s {
        std::string id;
        std::string ipv4;
        int location;

        std::string to_string() const {
                std::string s = {};
                s.append("xApp Id: ");
                s.append(id);
                s.append(", xApp Ipv4: ");
                s.append(ipv4);
                s.append(", xApp Location: ");
                s.append(std::to_string(location));
                return s;
        }

} xapp_profile_t;

namespace xrf {
namespace app {

class xrf_client {
	private:
		CURL *curl;
		CURLcode res;
		std::string datasend;
		//std::string readBuffer;
		nlohmann::json json_send;
		std::string content_type;	
		struct curl_slist *headers;

	public: 
		xrf_client();
		virtual ~xrf_client() = default;

		xrf_client(xrf_client const&) = delete;
		void operator=(xrf_client const &) = delete;
		
		void curl_create_handle(const std::string& uri, const std::string& data,
                         std::string& response_data, uint8_t http_version);
		/*
		 * curl handle with string data input
		 * @param[uri] : target address/port/path
		 * @param[data] : data to send : string
		 * @param[response_data] : response from target
		 * @param[http_versoin] : http version
		 * @return CURL
		 */

		void curl_create_handle(const std::string& uri, const nlohmann::json& data,
                         std::string& response_data, uint8_t http_version);
                /*
		 * curl handle with json data input
                 * @param[uri] : target address/port/path
                 * @param[data] : data to send : json object
                 * @param[response_data] : response from target
                 * @param[http_versoin] : http version
                 * @return void
                 */

		void curl_create_handle(const std::string& uri, const std::vector<std::string>& data,
                         std::string& response_data, uint8_t http_version);
                /*
		 * curl handle with string vector input 
                 * @param[uri] : target address/port/path
                 * @param[data] : data to send : vector string
                 * @param[response_data] : response from target
                 * @param[http_versoin] : http version
                 * @return void
                 */

                void curl_create_get_handle(const std::string& uri,
                         std::map<int, xapp_profile_t>& disc_map, uint8_t http_version,
			 const std::string& targetxApp, const std::string targetLoc);
                /*
                 * @param[uri] : target address/port/path
                 * @param[disc] : discovered xapp's map to be updated
                 * @param[http_version] : http version
		 * @param[targetxApp] : target functioanlity query
		 * @param[targetLoc] : target location query
                 * @return void
                 */

		void curl_create_token_req_handle(const std::string& uri, nlohmann::json& data,
				std::string& response_data, uint8_t http_version);
		/*
		 * create curl handle for oauth token request
		 * @param[uri] : target address
		 * @param[data] : data to send
		 * @param[response_data] : response from target
		 * @param[http_version] : http version
		 */

		void curl_create_jwks_req_handle(const std::string& uri,
			        		 std::unordered_map<std::string, std::string>& token_key_map,
			       			 uint8_t http_version, std::string& kid);
		/*
		 * create curl handle for jwks key request
		 * @param[uri] : target address
		 * @param[token_key_map] : token to public key map to be updated
		 * @param[http_version] : http version
		 * @param[kid] : key id query
		 *
		 */

                void curl_create_intro_req_handle(const std::string& uri,
                                                 uint8_t http_version, nlohmann::json& token,
						 bool& validity);
                /*
                 * create curl handle for jwks key request
                 * @param[uri] : target address
                 * @param[http_version] : http version
                 * @param[token] : token to send
                 *
                 */

		void curl_create_client_req(const std::string& uri,
					    uint8_t http_version, std::string& token);
		/*
		 * create client request
		 * @param[uri] : target address
		 * @param[http_version] : http version
		 * @param[token] : access token to use
		 * @param[dummy_content] : null content
		 */
	
                /*
                 * create curl handle for oauth token request
                 * @param[uri] : target address
                 * @param[data] : data to send
                 * @param[response_data] : response from target
                 * @param[http_version] : http version
                 */

		void to_json(nlohmann::json& j, const std::string& kv1, const std::string& kv2);
		/*
		 * @param[j] : empty json object to load
		 * @param[kv1] : keyvalue pair value1
		 * @param[kv2] : keyvalue pair value2
		 * return void
		 */

		void send_curl_easy(const std::string& uri, const std::string& data, 
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
