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

void xapp_main::register_with_xrf() {
	unsigned int wait = 10000;
	usleep(wait);
	//create_xappclient_profile();
	//send_xapp_registration_request();
}

void xapp_main::generate_uuid(){
	xappclient_instance_id = to_string(boost::uuids::random_generator()());
};


void xapp_main::create_xappclient_profile() {
	generate_uuid();

	//xappclient_instance_profile.set_xappclient_instance_id(xappclient_instance_id);
	//xappclient_instance_profile.set_xappclient_status("REGISTERED");
	//xappclient_instance_profile.set_xappclient_instance_name("xApp1");

}

void xapp_main::sendauth_to_xrf(const std::string& challenge, const std::string& xrfaddress){
	
	std::string response_from_xrf;;
	std::string str;

	spdlog::info("Creating challenge");
	xapp_msg_inst->create_final_msg(str);
	spdlog::info("Challenge created");

	spdlog::info("Creating Client");
	xrf_client_inst->curl_create_handle(xrfaddress, str, response_from_xrf, 1);
	std::cout << "Response from XRF: " << response_from_xrf << std::endl;
	/*
				Process for XRF ID authentication by xApp
	*/

	unsigned char xrf_challenge[RND_LENGTH];

	int xrf_auth_result = xapp_msg_inst->final_verification(response_from_xrf, xrf_challenge);

	if (xrf_auth_result == 1) spdlog::info("Rejoice! xApp authentication successful!");
	else if (xrf_auth_result == 0) spdlog::warn("Alas! xApp authentication failed!");
	else spdlog::warn("Unspecified signature verification error");

	spdlog::info("Client Created");
}


