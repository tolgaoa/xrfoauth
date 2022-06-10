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
xrf_msg* xrf_msg_inst = nullptr;

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
	
	std::string str1 = "temp1";
	xrf_client_inst->curl_create_handle(xrfaddress, challenge, str1, 1);
}





