/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 *
 *
 * ! file xrf_main.cpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/


#include "xrf_main.hpp"

#include <unistd.h>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/date_time/posix_time/time_formatters.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <chrono>


using namespace xrf::app;
using namespace std::chrono;

extern xrf_main* xrf_main_inst;
xrf_jwt* xrf_jwt_inst = nullptr;
xrf_msg* xrf_msg_inst = nullptr;

void xrf_main::access_token_request(
		const std::string& request_main, AccessTokenRsp& access_token_rsp, 
		int& http_code, const uint8_t http_version, 
		ProblemDetails& problem_details){

	std::map<std::string, std::string> request;
	std::vector<std::string> kvpairs;
	boost::split(kvpairs, request_main, boost::is_any_of("&"), boost::token_compress_on);

	for (auto i : kvpairs){
		std::vector<std::string> kv;
		boost::split(kv, i, boost::is_any_of(","), boost::token_compress_on);
		if (kv.size() != 3){
			std::cout << "Invalid Request" << std::endl;
		}else request[kv[0]] = kv[1];	

		printf("(Key, Value):  %s, %s \n", kv[0].c_str(), kv[1].c_str());
	}

	//JWT Object created here
	std::string sign = {};
	bool outcome = false;

	outcome = xrf_jwt_inst->generate_signature("00001", "1", "00002", "A1", sign);
	spdlog::info("JWT Access Token Generated");
	spdlog::info(sign);
	spdlog::info("JWT Access Token Signed");
	access_token_rsp.setAccessToken(sign);
	access_token_rsp.setTokenType("Bearer");
	http_code = 200;
};

void xrf_main::handle_auth_request
	(const std::string& request_main, InitAuthRsp& in_auth_rsp, 
	 int& http_code, const uint8_t http_version, 
	 ProblemDetails& problem_details){

	std::map<std::string, std::string> request;
        std::vector<std::string> kvpairs;
        boost::split(kvpairs, request_main, boost::is_any_of("&"), boost::token_compress_on);

        std::vector<std::string> kv;
	for (auto i : kvpairs){
                //std::vector<std::string> kv;
                boost::split(kv, i, boost::is_any_of(":"), boost::token_compress_on);
                if (kv.size() != 2){
                        spdlog::warn("Invalid Request--Expecting single KVpair--Received more");
                }else request[kv[0]] = kv[1];
		printf("(Key, Value):  %s, %s \n", kv[0].c_str(), kv[1].c_str());
		//spdlog::info("(Key, Value):  %s, %s \n", kv[0].c_str(), kv[1].c_str());
        }

	spdlog::info("Starting processing of Incoming Authentication Request");	
	//------Processing the incoming string from authentication of the xApp-------
	std::string rec_str = kv[1];
	rec_str.erase(rec_str.begin()+0);
	rec_str.erase(rec_str.end()-1);
	rec_str.erase(rec_str.end()-1);

	unsigned char xapp_challenge[RND_LENGTH];

	int xapp_auth_result = xrf_msg_inst->final_verification(rec_str, xapp_challenge);

	if (xapp_auth_result == 1) spdlog::info("Rejoice! xApp authentication successful!");
	else if (xapp_auth_result == 0) spdlog::warn("Alas! xApp authentication failed!");
	else spdlog::warn("Unspecified signature verification error");

	std::string response_challenge;
	xrf_msg_inst->create_final_msg(response_challenge, xapp_challenge);

	std::cout << "\nChallenge to be sent to xApp:\n" << response_challenge << std::endl;
	
        const std::string str1 = response_challenge;
	//-----------------------------------------------------------------
		
	spdlog::info("Finished processing Incoming Authentication Request");
	in_auth_rsp.setChallenge(str1);

};
