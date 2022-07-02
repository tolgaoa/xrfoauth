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


// Implemented in xapp_main for now
void xapp_jwt::extract_token_jwks(std::string& bearer, std::string& kid) {
};

void xapp_jwt::validate_token_remote(std::string& bearer, std::string& kid) {
};
