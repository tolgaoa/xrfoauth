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

#include "xappclient_main.hpp"

#include <unistd.h>

using namespace xappclient;

extern xappclient_main* xappclient_main_inst;

void xappclient_main::register_with_xrf() {
	unsigned int wait = 10000;
	usleep(wait);
	create_xappclient_profile();
	//send_xapp_registration_request();
}

void xappclient_main::create_xappclient_profile() {
	generate_uuid();


}
