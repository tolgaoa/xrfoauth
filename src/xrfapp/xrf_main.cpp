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
#include "logger.hpp"



using namespace xrf::app;
using namespace std::chrono;

xrf_jwt* jwt_instance = NULL;

void xrf_main::access_token_request(const std::string& request_main, AccessTokenRsp& ac_tok_rsp, int& http_code, const uint8_t http_version, ProblemDetails& problem_details){

	std::map<std::string, std::string> access_token_req;
	std::vector<std::string> values;
	boost::split(values, request_main, boost::is_any_of("&"), boost::token_compress_on);

	for (auto i : values){
		std::vector<std::string> value;
		boost::split(value, i, boost::is_any_of("&"), boost::token_compress_on);
		if (value.size() != 2){
			Logger::xrf_main().debug("Invalid request");
		}else access_token_req[value[0]] = value[1];	

		Logger::xrf_main().debug("(Key, value): %s, %s", value[0].c_str(), value[1].c_str());
	}
};
