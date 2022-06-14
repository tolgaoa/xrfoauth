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

/*std::string& xapp_main::create_auth_challenge(){
	
	//auto finalciphertext_s;
        unsigned char final_cipher_buf[FINAL_CIPHER_LEN];
        spdlog::info("Creating challenge");
        xapp_msg_inst->create_final_msg(final_cipher_buf);
        spdlog::info("Challenge created");

        spdlog::debug("Cast challenge from unsigned char to string");   
        std::ostringstream oss;
        for(int i = 0; i < FINAL_CIPHER_LEN; ++i) 
        {
              oss << std::hex << std::setw(2) << std::setfill('0') << +final_cipher_buf[i];
        }
        auto finalciphertext_s = oss.str();

        spdlog::debug(finalciphertext_s);

	return finalciphertext_s;

}
*/

void xapp_main::sendauth_to_xrf(const std::string& challenge, const std::string& xrfaddress){
	
	std::string str1 = "temp1";

	unsigned char final_cipher_buf[FINAL_CIPHER_LEN];

	std::string str;
	spdlog::info("Creating challenge");
	//str = td::string& strxapp_msg_inst->create_final_msg(final_cipher_buf, str);
	str = xapp_msg_inst->create_final_msg(final_cipher_buf);
	spdlog::info("Challenge created");
	spdlog::debug("String is:");
	spdlog::debug(str);

	/*spdlog::debug("Cast challenge from unsigned char to string");	
	std::ostringstream oss;
	for(int i = 0; i < FINAL_CIPHER_LEN; ++i) 
	{
	      oss << std::hex << std::setw(2) << std::setfill('0') << +final_cipher_buf[i];
	}
	auto str = oss.str();	
	
	spdlog::debug(str);
	*/
	spdlog::info("Creating Client");
	xrf_client_inst->curl_create_handle(xrfaddress, str, str1, 1);
	spdlog::info("Client Created");
}





