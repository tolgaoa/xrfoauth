/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 *
 * Library for generating a JSON Web Token
 *
 * ! file xrf_jwt.hpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#ifndef FILE_XRF_JWT_HPP_SEEN
#define FILE_XRF_JWT_HPP_SEEN

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
#include <cassert>

#include <keys.hpp>
#include <spdlog/spdlog.h>

#include <jwt/jwt.hpp>
//#include <jwt-cpp/jwt.h>

namespace xrf {
namespace app {

class xrf_jwt{
	public:
		void test_jwt();
		/*
		 * testing
		 */

		bool generate_signature(const std::string& xapp_consumer_id,
                                        const std::string& target_xapp_id,
                                        std::string& signature, 
					std::unordered_map<int, std::string>& jwks,
					std::string& scope, int& kidout, std::string& pub_key);
                /*
                 * Generate signature for the requested consumer trying to access resources
                 * @param {xapp_consumer_id}: the id of the consumer xapp
                 * @param {target_xapp_id}: instance ID of the xapp service producer
                 * @param {signature}: generated signature
		 * @param {jwks} : JSON Web key set for kid and public key mapping
		 * @param {scope} : access rights of the token
                 * return void
                 */

		//Overload generate_key_pair
                bool generate_key_pair(std::unordered_map<std::string, EVP_PKEY*>& jwks,
                                    std::string& kid,  EVP_PKEY *priv_key) ;
                /*
                 * Get the secret key
                 * @param {scope}: names of the xapp services that the consumer is trying to access
                 * @param {target_xapp_id}: instance id of the xapp service producer
                 * @param {key}: secret key [K]
                 * return void
                 */

                bool generate_key_pair(std::unordered_map<int, std::string>& jwks, 
				       std::string& priv_key, int& kid, std::string& pub_key);
                /*
                 * Get the secret key
                 * @param {scope}: names of the xapp services that the consumer is trying to access
                 * @param {target_xapp_id}: instance id of the xapp service producer
                 * @param {key}: secret key [K]
                 * return void
                 */

		std::pair<EVP_PKEY*,EVP_PKEY*> GetKeyRSApair();
		/*
		 * generate RSA key pair
		 * return std::pair priv and pub key
		 */
		
		std::pair<std::string, std::string> selectRSApair();
		/*
		 * select from pre-created list of keys
		 * return std::pair priv and pub key
		 */

	private:
		const int kBits = 1024;
		const int kExp = 3;
		std::unordered_map<int, std::string> oauth_prv_keys;
		std::unordered_map<int, std::string> oauth_pub_keys;

};

} // app namespace defined
} // xrf namespace defined

#endif
