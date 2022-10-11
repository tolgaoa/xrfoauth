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


using namespace xrf::app;
using namespace std::chrono;

extern xrf_main* xrf_main_inst;
xrf_jwt* xrf_jwt_inst = nullptr;
xrf_msg* xrf_msg_inst = nullptr;
xapp_meta* xapp_meta_inst = nullptr;

std::unordered_map<std::string, xapp_profile_t> profile_i;
std::unordered_map<std::string, xapp_profile_t> profile_f;
//std::unordered_map<std::string, EVP_PKEY*> jwks; // kid .at() tokenpubkey where key is EVP_PKEY
std::unordered_map<int, std::string> jwks; // kid .at() tokenpubkey where key is plaintext

template<class T> std::string toString(const T& x)
{
  std::ostringstream ss;
  ss << x;
  return ss.str();
}

void xrf_main::access_token_request(
		const std::string& request_main, AccessTokenRsp& access_token_rsp, 
		int& http_code, const uint8_t http_version, 
		ProblemDetails& problem_details){

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

	outcome = xrf_jwt_inst->generate_signature(request.at("requester_ID"), request.at("target_ID"), sign, jwks, request.at("scope"));
	spdlog::info("JWT Access Token Generated");
	spdlog::debug(sign);
	spdlog::info("JWT Access Token Signed");
	access_token_rsp.setAccessToken(sign);
	access_token_rsp.setTokenType("Bearer");
	http_code = 200;

	//Uncomment to test JWT encode and decode
	//xrf_jwt_inst->test_jwt();
};

void xrf_main::handle_auth_request
	(const std::string& request_main, InitAuthRsp& in_auth_rsp, 
	 int& http_code, const uint8_t http_version, 
	 ProblemDetails& problem_details){

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
	in_auth_rsp.setChallenge(str1);

};

void xrf_main::handle_reg_request
	(const std::string& request_main, 
	 int& http_code, const uint8_t http_version, 
	 ProblemDetails& problem_details) {

	std::map<std::string, std::string> request;
        std::vector<std::string> kvpairs;
	std::vector<std::string> kvpairs1;
        boost::split(kvpairs, request_main, boost::is_any_of(","), boost::token_compress_on);
	
	std::string xfunc;
	std::string xid;	

        std::vector<std::string> kv;
	std::string reqmod = request_main;
	
	reqmod.erase(remove(reqmod.begin(), reqmod.end(), '"'), reqmod.end()); 
	reqmod.erase(remove(reqmod.begin(), reqmod.end(), '{'), reqmod.end()); 
	reqmod.erase(remove(reqmod.begin(), reqmod.end(), '}'), reqmod.end()); 
	reqmod.erase(remove(reqmod.begin(), reqmod.end(), ' '), reqmod.end()); 

        boost::split(kvpairs, reqmod, boost::is_any_of(","), boost::token_compress_on);

	spdlog::info("=============================================");
	spdlog::info("=============================================");
        for (auto i : kvpairs){
                boost::split(kv, i, boost::is_any_of(":"), boost::token_compress_on);
                request[kv[0]] = kv[1];
                spdlog::info("\t(Key, Value):  {} , {}", kv[0].c_str(), kv[1].c_str());
		if (kv[0] == "xAppFunc") xfunc = kv[1];
		if (kv[0] == "xAppInstanceId") xid = kv[1];
		kvpairs1.push_back(kv[1]);
        }	
	spdlog::info("=============================================");
	spdlog::info("=============================================");

	std::string imap = "imap";
	std::string fmap = "fmap";
	xapp_meta_inst->register_profile(kvpairs1, xid, imap, profile_i);
	xapp_meta_inst->register_profile(kvpairs1, xfunc, fmap, profile_f);

	xapp_meta_inst->display_map(profile_i);

}


void xrf_main::handle_search_xapp_instances(const std::string& targetxApp, const std::string& targetLoc,
                                	std::vector<std::string>& search_result, int& http_code, 
					const uint8_t http_version, ProblemDetails& problem_details){
	spdlog::debug("Handling xApp Discovery request and searching for a set of xApp Instances");
	
	for (auto i : profile_i){
		if (i.second.xapp_instance_func == targetxApp){
			spdlog::debug("Found xApp: {}", i.second.xapp_instance_id);
			search_result.push_back(i.second.xapp_instance_id);
		}
	}

	if (search_result.empty()) spdlog::warn("No xApp profile found corresponding to desired request");
	else http_code = 200;
};

void xrf_main::vector_to_json(std::vector<std::string>& vector_ids, nlohmann::json& json_data){

	spdlog::debug("Converting search result to JSON");
	std::string s;

	for (int i = 0; i < vector_ids.size(); i++) {
		s = std::to_string(i);
		//std::cout << vector_ids[i] << std::endl;
		json_data["&"+s] = { {"id" , vector_ids[i]} , 
				 {"location" , profile_i.at(vector_ids[i]).xapp_instance_loc + '&'} ,
				 {"ipv4" , profile_i.at(vector_ids[i]).ipv4_addresses } };
	}
	spdlog::debug("Finished converting search result to JSON");
};

void xrf_main::fetch_token_key(std::string& kid, std::string& token_pub_key) {

	spdlog::debug("Processing for key id: {}", kid);	
	int kid_i = std::stoi(kid);
	token_pub_key = jwks.at(kid_i);
	spdlog::debug("Found pub key: {}", token_pub_key);

};

void xrf_main::validate_token(const std::string& token, bool& validity){

	using namespace jwt::params;

	std::vector<std::string> kvpairs;
        boost::split(kvpairs, token, boost::is_any_of(","), boost::token_compress_on);
        std::vector<std::string> kv;
	std::string proc_token;

        for (auto i : kvpairs){
                i.erase(remove(i.begin(), i.end(), '"'), i.end());
                i.erase(remove(i.begin(), i.end(), '{'), i.end());
                i.erase(remove(i.begin(), i.end(), '}'), i.end());

                boost::split(kv, i, boost::is_any_of(":"), boost::token_compress_on);
                proc_token = kv[1];
                spdlog::debug("(Key, Value):  {}, {}", kv[0], kv[1]);
        }

        std::string kid;
        auto decoded = jwt::decode(proc_token, algorithms({"none"}), verify(false));

        spdlog::debug("======Decoding Token Header and Payload======");
        spdlog::debug("===Header===");
        spdlog::debug("{}", toString(decoded.header()));
        spdlog::debug("===Payload===");
        spdlog::debug("{}", toString(decoded.payload()));

        std::string header_raw = toString(decoded.header());
        std::vector<std::string> header;
        boost::split(header, header_raw, boost::is_any_of(","), boost::token_compress_on);
        for (auto i : header){
                i.erase(remove(i.begin(), i.end(), '"'), i.end());
                i.erase(remove(i.begin(), i.end(), '{'), i.end());
                i.erase(remove(i.begin(), i.end(), '}'), i.end());

                std::vector<std::string> hkv;
                boost::split(hkv, i, boost::is_any_of(":"), boost::token_compress_on);
                for (auto k : hkv){
                        if (hkv[0] == "kid") {
                                kid = hkv[1];
                        }
                }
        }
        spdlog::debug("Key ID is: {}", kid);

        std::error_code ec;
        auto dec_obj = jwt::decode(token, algorithms({"RS256"}), ec, secret(jwks.at(std::stoi(kid))), verify(true));
        //If there is a verification error, uncomment to see the code
	//std::cout << ec << std::endl;
        assert (ec);
        validity = true;
	spdlog::debug("Introspection Complete");


};

