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

        jwt::jwt_object obj{jwt::params::algorithm("ES256"),
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
                std::string keypriv =
R"(-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBeLCgapjZmvTatMHaYX3A02+0Ys3Tr8kda+E9DFnmCSiCOEig519fT
13edeU8YdDugBwYFK4EEACKhZANiAASibEL3JxzwCRdLBZCm7WQ3kWaDL+wP8omo
3e2VJmZQRnfDdzopgl8r3s8w5JlBpR17J0Gir8g6CVBA6PzMuq5urkilppSINDnR
4mDv0+9e4uJVQf3xwEv+jywNUH+wbPM=
-----END EC PRIVATE KEY-----)";

	// Will complete this later. For now it can return the key from the class object. 
        key = keypriv;
        return true;

}

void xrf_jwt::test_jwt(){

        using namespace jwt::params;

        //auto key = "secret";  // Secret to use for the algorithm

static const char* key1 = 
R"(-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----)";

static const char* keypub1 = 
R"(ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCmR9ZlrWbm9FuZF3hU6i92GdAyTdM78F5lcRdiL4gOSNGrdGpvGXlpJ/lqnPc/Rgv+a0K1F5ejdAFt/pC8pNPvqiZ0H3GtbpnSOOGg4rk8OWJA1EHug34FUtswmE1yORgd/2bso4/0MjmxPdjvO/TmNJLSUaRLV+DdroUVAdBCPLotYSkPvWIyKQU5N4/60kUQnSnw+8IQSCXajn5mHmkj7SPmcmUk3bHW3iSY99YiGgm2vZ+o68T7g5BsZwd9hafa2Gmd0r337mX+oAv14XyG7kTBwB24FQncvMg/UP6s8x4ur+Pgiv4ZjBgA788lPTwiKyqnNslLuGm9/4NiLbxkrXtolOqd/7047WMxcQEIPH/jdvq7GZBtHqfnB4njMOETDJlJ7J3njpSsbHAl8EeQgERetuqUzE96w6WVh02jzEfLK097aVK3hlfZRQKgqvz1pc/bGwrsJbktxtQfA6/GLCXkdRCZF7op9GJK11KERezMngCfw48Dk98diaR59mk= taport@taport-ThinkPad-T540p)";

std::string keypub =
    R"(-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEomxC9ycc8AkXSwWQpu1kN5Fmgy/sD/KJ
qN3tlSZmUEZ3w3c6KYJfK97PMOSZQaUdeydBoq/IOglQQOj8zLqubq5IpaaUiDQ5
0eJg79PvXuLiVUH98cBL/o8sDVB/sGzz
-----END PUBLIC KEY-----)";

std::string key =
R"(-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBeLCgapjZmvTatMHaYX3A02+0Ys3Tr8kda+E9DFnmCSiCOEig519fT
13edeU8YdDugBwYFK4EEACKhZANiAASibEL3JxzwCRdLBZCm7WQ3kWaDL+wP8omo
3e2VJmZQRnfDdzopgl8r3s8w5JlBpR17J0Gir8g6CVBA6PzMuq5urkilppSINDnR
4mDv0+9e4uJVQf3xwEv+jywNUH+wbPM=
-----END EC PRIVATE KEY-----)";

	std::cout << "Create string view of the private key" << std::endl;
	jwt::string_view sv = key;
	std::cout << key << std::endl;

	std::cout << "Create string view of the public key" << std::endl;
	jwt::string_view sv1 = keypub;
	std::cout << keypub << std::endl;

	std::cout << "Create JWT Object" << std::endl;
	// Create JWT object
        jwt::jwt_object obj{algorithm("ES256"), payload({{"some", "payload"}}),
                      secret(key)};

	std::cout << "encode and sign the object" << std::endl;
        // Get the encoded string/assertion
        auto enc_str = obj.signature();
        std::cout << enc_str << std::endl;

        // Decode
        auto dec_obj = jwt::decode(enc_str, algorithms({"ES256"}), secret(keypub));
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

