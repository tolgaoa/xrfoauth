/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 * 
 * Specific subfunctions of the XRF for isolation
 *
 *
 * ! file func.hpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#ifndef FILE_XRF_AUTH_HPP_SEEN
#define FILE_XRF_AUTH_HPP_SEEN

#include <string>
#include <iostream>

#include "spdlog/spdlog.h"

#include <gmp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string>

#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/router.h>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

#include "xrf_jwt.hpp"

namespace xrf {
namespace app {

class handlers {
	public: 
                void validate_token(const std::string& token, std::string& validity);
                /*
                 * validate token for introspection endpoint
                 * @param[token] : token reqeust coming from client
                 * @param[validity] : valid or not
                 * return void
                 */
};


}
}
#endif


