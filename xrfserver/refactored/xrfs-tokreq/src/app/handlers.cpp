/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 * 
 * Specific subfunctions of the XRF for isolation
 *
 *
 * ! file func.cpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/


#include "handlers.hpp"


using namespace xrf::app;
xrf_jwt* xrf_jwt_inst = nullptr;

std::unordered_map<int, std::string> jwks; // kid .at() tokenpubkey where key is plaintext

void handlers::access_token_request(
                const std::string& request_main, std::string& token_rsp,
                int& http_code, const uint8_t http_version) {

        std::map<std::string, std::string> request;
        std::vector<std::string> kvpairs;
        boost::split(kvpairs, request_main, boost::is_any_of(","), boost::token_compress_on);

        for (auto i : kvpairs){
                i.erase(remove(i.begin(), i.end(), '"'), i.end());
                i.erase(remove(i.begin(), i.end(), '{'), i.end());
                i.erase(remove(i.begin(), i.end(), '}'), i.end());

                std::vector<std::string> kv;
                boost::split(kv, i, boost::is_any_of(":"), boost::token_compress_on);
                request[kv[0]] = kv[1];

                spdlog::debug("(Key, Value):  {}, {}", kv[0], kv[1]);
        }

        //JWT Object created here
        std::string sign = {};
        bool outcome = false;

        std::string scope = "read, write";

	int kid;
	std::string pubkeypair;

        outcome = xrf_jwt_inst->generate_signature(request.at("requester_ID"), request.at("target_ID"), sign, jwks, request.at("scope"), kid,  pubkeypair);


        spdlog::debug("JWT Access Token Signed: {}", sign);
        spdlog::debug("Key ID is: {}", kid);
        spdlog::debug("Pub_key pair is: {}", pubkeypair);	

	token_rsp = sign + "&" + std::to_string(kid) + "&" + pubkeypair;
/*
        access_token_rsp.setAccessToken(sign);
        access_token_rsp.setTokenType("Bearer");
        http_code = 200;
*/
        //Uncomment to test JWT encode and decode
        //xrf_jwt_inst->test_jwt();
};

