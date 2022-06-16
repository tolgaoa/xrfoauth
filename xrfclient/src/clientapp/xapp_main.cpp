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

void xapp_main::register_with_xrf() {
	unsigned int wait = 10000;
	usleep(wait);
	//create_xappclient_profile();
	//send_xapp_registration_request();
}

void xapp_main::generate_profile(std::string& instance_id_v, std::string& instance_name_v,
		  std::string& instance_status_v, std::string& func_v,
		  std::vector<std::string>& addresses){
        xapp_profile_inst->create_profile(instance_id_v, instance_name_v, instance_status_v, func_v, addresses);
};

void xapp_main::display_profile() {
	xapp_profile_inst->display();
};


void xapp_main::sendauth_to_xrf(const std::string& challenge, const std::string& xrfaddress){
	
	std::string response_from_xrf;;
	std::string str;

	spdlog::info("Creating challenge");
	xapp_msg_inst->create_final_msg(str);
	spdlog::info("Challenge created");
	//spdlog::debug("String is:");
	//spdlog::debug(str);

	spdlog::info("Creating Client");
	xrf_client_inst->curl_create_handle(xrfaddress, str, response_from_xrf, 1);
	std::cout << "Response from XRF: " << response_from_xrf << std::endl;
	spdlog::info("Client Created");


}


