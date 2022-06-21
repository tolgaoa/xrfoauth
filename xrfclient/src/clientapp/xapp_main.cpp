/*
 * Client side of the xApp authorization framework to be integrated into the reference RAN Intelligent 
 * Controller (RIC) of the Linux Foundation (LF) for distributing access tokens to xApps from an 
 * OAUTH 2.0 server using JSON web tokens as the execution method of the tokens
 *
 *
 * ! file xappclient_main.cpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#include "xapp_main.hpp"
#include <unistd.h>

using namespace xrf::app;

extern xapp_main* xapp_main_inst;
xrf_client* xrf_client_inst = nullptr;
xapp_msg* xapp_msg_inst = nullptr;
xapp_profile* xapp_profile_inst = nullptr;

void xapp_main::register_with_xrf(const std::string& xrfaddress) {
	std::string response_from_xrf;
	std::string str = "test";	
	
	nlohmann::json data;
	std::vector<std::string> data_s;
	xapp_profile_inst->profile_to_json(data);
	xapp_profile_inst->profile_to_vector_s(data_s);
	xrf_client_inst->curl_create_handle(xrfaddress, data, response_from_xrf,1);
	
}

void xapp_main::generate_profile(std::string instance_id_v, std::string instance_name_v,
		  std::string instance_status_v, std::string func_v,
		  std::string addresses, std::string loc_v, int cap){
	
	xapp_profile *xapp_p = new xapp_profile(instance_id_v, instance_name_v, instance_status_v, func_v, addresses, loc_v, cap);
	xapp_profile_inst = xapp_p;
};

void xapp_main::display_profile() {
	xapp_profile_inst->display();
};


void xapp_main::sendauth_to_xrf(const std::string& challenge, const std::string& xrfaddress){
	
	std::string response_from_xrf;
	std::string str;

	spdlog::info("Creating challenge");
	xapp_msg_inst->create_final_msg(str);
	spdlog::info("Challenge created");

	xrf_client_inst->curl_create_handle(xrfaddress, str, response_from_xrf, 1);
	spdlog::info("Response from XRF: {}", response_from_xrf);
	//-----------------Process for XRF ID authentication by xApp----------------------------
	unsigned char xrf_challenge[RND_LENGTH];
	int xrf_auth_result = xapp_msg_inst->final_verification(response_from_xrf, xrf_challenge);
	if (xrf_auth_result == 1) spdlog::info("Rejoice! xApp authentication successful!");
	else if (xrf_auth_result == 0) spdlog::warn("Alas! xApp authentication failed!");
	else spdlog::error("Unspecified signature verification error");
}

void xapp_main::send_discovery_request(std::string& xrfaddressbase, const std::string& targetxApp, const std::string& targetLoc){

	spdlog::info("Sending xApp Disocovery Request to XRF");
	std::string response_from_xrf;
	xrf_client_inst->curl_create_get_handle(xrfaddressbase, response_from_xrf, 1, targetxApp, targetLoc);
};
