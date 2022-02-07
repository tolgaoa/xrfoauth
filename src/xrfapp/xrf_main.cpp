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

#include "xrf_jwt.hpp"
//#include "logger.hpp"



using namespace xrf::app;
using namespace std::chrono;

extern xrf_main* xrf_main_inst;
xrf_jwt* xrf_jwt_inst = nullptr;

void xrf_main::access_token_request(
		const std::string& request_main, AccessTokenRsp& access_token_rsp, 
		int& http_code, const uint8_t http_version, 
		ProblemDetails& problem_details){

	std::map<std::string, std::string> access_token_req;
	std::vector<std::string> key_values;
	boost::split(key_values, request_main, boost::is_any_of("&"), boost::token_compress_on);

	for (auto i : key_values){
		std::vector<std::string> key_value;
		boost::split(key_value, i, boost::is_any_of(","), boost::token_compress_on);
		if (key_value.size() != 2){
			std::cout << "Invalid Request" << std::endl;
			//Logger::xrf_main().debug("Invalid request");
		}else access_token_req[key_value[0]] = key_value[1];	

		//Logger::xrf_main().debug("(Key, value): %s, %s", value[0].c_str(), value[1].c_str());
		printf("(Key, Value):  %s, %s \n", key_value[0].c_str(), key_value[1].c_str());
	}

	//Generate the JWT object
	std::string signature = {};
	bool outcome = false;

	outcome = xrf_jwt_inst->generate_signature("00001", "1", "00002", "A1", signature);
	std::cout << signature << std::endl;

	access_token_rsp.setAccessToken(signature);
	access_token_rsp.setTokenType("Bearer");
	http_code = 200;

	

};
