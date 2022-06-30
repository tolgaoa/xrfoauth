/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 *
 * Library for handling a JSON Web Token
 *
 * ! file xrf_jwt.cpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#include "xapp_jwt.hpp"

#include <typeinfo>
#include <sstream>

using namespace xrf::app;

extern xapp_jwt* xapp_jwt_inst;

template<class T> std::string toString(const T& x)
{
  std::ostringstream ss;
  ss << x;
  return ss.str();
}


void xapp_jwt::validate_token_jwks(std::string& bearer, std::string& kid) {
	auto decoded = jwt::decode(bearer);

	for(auto& e : decoded.get_header_claims()){
		//std::cout << e.first << " = " << e.second << std::endl;
		if (e.first == "kid") {
			kid = toString(e.second);
			kid = kid.substr(1, kid.size() - 2);
			//std::cout << "Key ID is: " << kid << std::endl;
		}	
	}


	if(kid.empty()) spdlog::error("Did not find key id in JWT header");
	else spdlog::debug("Key id is: {}", kid);
};

void xapp_jwt::validate_token_remote(std::string& bearer, std::string& kid) {

};
