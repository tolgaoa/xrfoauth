/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 *
 * Library for handling a JSON Web Token
 *
 * ! file xapp_jwt.hpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#ifndef FILE_XAPP_JWT_HPP_SEEN
#define FILE_XAPP_JWT_HPP_SEEN

#include <string>
#include <chrono>
#include <ctime>
#include <unordered_map>
#include <random>

#include <stdio.h>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <exception>

//#include <keys.hpp>
#include <spdlog/spdlog.h>


#include <jwt/jwt.hpp>
//include <jwt-cpp/jwt.h>

namespace xrf {
namespace app {

class xapp_jwt {
	public:
		void extract_token_jwks (std::string& bearer, std::string& kid);
		/*
		 * validate JWT through the JWKS endpoint by fetching a public key
		 * @param[bearer] : JWT received
		 * @param[kid] : key id extracted from header
		 * return void
		 */

		void validate_token_remote (std::string& bearer, std::string& kid);
		/*
		 * validate JWT throught remote introspection
		 * @param[bearer] : JWT received
		 * @param[kid] : key id extracted from header
		 * return void
		 */




};


} //namespace app
} //namespace xrf


#endif
