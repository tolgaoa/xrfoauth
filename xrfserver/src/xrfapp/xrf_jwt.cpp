/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 *
 *
 * ! file xrf_jwt.cpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#include "xrf_jwt.hpp"

#include <string>
#include <iostream>

#include <jwt/jwt.hpp>


using namespace xrf::app;

bool xrf_jwt::generate_signature(const std::string& xapp_consumer_id, const std::string& scope,
                                 const std::string& target_xapp_id,
                                 const std::string& xrf_id, std::string& signature) const {

        std::string key;
        get_secret_key(scope, target_xapp_id, key);

        jwt::jwt_object obj{jwt::params::algorithm("RS256"),
                        jwt::params::payload({{"iss", xrf_id},
                                            {"sub", xapp_consumer_id},
                                            {"aud", target_xapp_id},
                                            {"scope", scope},
                                            {"exp", "1000"}}),  // seconds
                        jwt::params::secret(key)};

        signature = obj.signature();
        return true;

}


bool xrf_jwt::get_secret_key(const std::string& scope, const std::string& target_xapp_id,
                             std::string& key) const {

	// Will complete this later. For now it can return the key from the class object. 
        key = "secret";
        return true;

}

void xrf_jwt::test_jwt(){

        using namespace jwt::params;

        //auto key = "secret";  // Secret to use for the algorithm
        auto key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCxqmqi+wZv8uKr3GPkxn35PECHNgUQuvh1thb4QaXQd4lSASylGwvN0UGRtw2I988d5X9pg8JM3w2MfoMt+YcEkIZDkFssZMXfA7woTmX3Yy8q6Rj7JAj0rRVqF52Vukg1nJzM3w5FVfcmejWhgVPinFreLRNCb6NUuoX0mbJ4nNvW7+5hgAjaHikTZp+iJryXvW2WX+vSyLaHJHDa9kYNEvBQuhAROd8Rr9clDAcivIGD+gMwDKiDilm1LYSx7khTtJj2jVV1BwpyUWom89eyQmqlpbCfSVVkpGSaFA/vAEBxV3WUuuGxRIDd4otTZo0SoMYgzFjbGpk3C+iATPSXTWUVVMAeAkoURQRTNM2sUjyHTBEAAcIDm9jxSf39mEI6TFmEE/s4fJWAg8og2CrWTSmmEOAZKA8T5RoN0Q4vXb660PC/H8BN91+HDLwY/e37W9kMKwQv7sOSX3OU8wjXZqNg77Z09eauw4eiZo4eyOsYrdwNjCrTVcKvImF3S9M= taport@taport-ThinkPad-T540p"; 
        
	std::cout << "Create JWT Object" << std::endl;
	// Create JWT object
        jwt::jwt_object obj{algorithm("RS256"), payload({{"some", "payload"}}),
                      secret(key)};

	std::cout << "encode and sign the object" << std::endl;
        // Get the encoded string/assertion
        auto enc_str = obj.signature();
        std::cout << enc_str << std::endl;

        // Decode
        auto dec_obj = jwt::decode(enc_str, algorithms({"HS256"}), secret(key));
        std::cout << dec_obj.header() << std::endl;
        std::cout << dec_obj.payload() << std::endl;
	std::cout << "token printed" << std::endl;
}




/*int main (){


	using namespace jwt::params;

        auto key = "secret";  // Secret to use for the algorithm
        // Create JWT object
        jwt::jwt_object obj{algorithm("HS256"), payload({{"some", "payload"}}),
                      secret(key)};

        // Get the encoded string/assertion
        auto enc_str = obj.signature();
        std::cout << enc_str << std::endl;

        // Decode
        auto dec_obj = jwt::decode(enc_str, algorithms({"HS256"}), secret(key));
        std::cout << dec_obj.header() << std::endl;
        std::cout << dec_obj.payload() << std::endl;

	std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
    	auto decoded = jwt::decode(token);

    	for(auto& e : decoded.get_payload_claims())
        	std::cout << e.first << " = " << e.second << std::endl;

	auto verifier = jwt::verify()
    		.allow_algorithm(jwt::algorithm::hs256{ "secret" })
    		.with_issuer("auth0");

	verifier.verify(decoded);

	auto jwttoken = jwt::create()
    		.set_issuer("auth0")
    		.set_type("JWS")
    		.set_payload_claim("sample", jwt::claim(std::string("test")))
    		.sign(jwt::algorithm::hs256{"secret"});

	std::cout << jwttoken << std::endl;

}*/

