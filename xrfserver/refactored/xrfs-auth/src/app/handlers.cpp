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
xrf_msg* xrf_msg_inst = nullptr;

void handlers::handle_auth_request(
			const std::string& request_main, std::string& in_auth_rsp, 
			int& http_code, const uint8_t http_version) {

        std::map<std::string, std::string> request;
        std::vector<std::string> kvpairs;
        boost::split(kvpairs, request_main, boost::is_any_of("&"), boost::token_compress_on);

        std::vector<std::string> kv;

        spdlog::info("=============================================");
        spdlog::info("=============================================");
        for (auto i : kvpairs){
                boost::split(kv, i, boost::is_any_of(":"), boost::token_compress_on);
                if (kv.size() != 2){
                        spdlog::warn("Invalid Authentication Request--Expecting single KVpair--Received more");
                }else request[kv[0]] = kv[1];
                spdlog::debug("(Key, Value):  {} , {}", kv[0].c_str(), kv[1].c_str());
        }
        spdlog::info("=============================================");
        spdlog::info("=============================================");

        spdlog::info("Starting processing of Incoming Authentication Request");
        //------Processing the incoming string from authentication of the xApp-------
        std::string rec_str = kv[1];
        rec_str.erase(rec_str.begin()+0);
        rec_str.erase(rec_str.end()-1);
        rec_str.erase(rec_str.end()-1);

        unsigned char xapp_challenge[RND_LENGTH];
        int xapp_auth_result = xrf_msg_inst->final_verification(rec_str, xapp_challenge);

        if (xapp_auth_result == 1) spdlog::info("Rejoice! xApp authentication successful!");
        else if (xapp_auth_result == 0) spdlog::warn("Alas! xApp authentication failed!");
        else spdlog::warn("Unspecified signature verification error");

        std::string response_challenge;
        xrf_msg_inst->create_final_msg(response_challenge, xapp_challenge);

        spdlog::debug("\nChallenge to be sent to xApp: {}", response_challenge);

        const std::string str1 = response_challenge;
        //-----------------------------------------------------------------
        spdlog::info("Finished processing Incoming Authentication Request");
        //in_auth_rsp.setChallenge(str1);
	in_auth_rsp = str1;

};
