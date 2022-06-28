#include "xapp_main.hpp"
#include "xrf_client.hpp"
#include "xapp_profile.hpp"
#include "xrfc-api-server.h"

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <thread>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using namespace xrf::app;
using namespace Pistache;

xapp_main* xapp_main_inst = nullptr;
XRFcApiServer* api_server = nullptr;

int main(int argc, char** argv){
	
	//Set log level debug
	spdlog::set_level(spdlog::level::debug);
	
	//---------------------------Create xApp Profile-----------------------------	
	spdlog::info("Creating xApp Profile");
	boost::uuids::uuid uuid = boost::uuids::random_generator()();
        std::string instance_id_v = to_string(uuid);
        std::string instance_name_v = "testxApp1";
        std::string instance_status_v = "Authenticated";
        std::string func_v = "TS";
	std::string addresses = "172.17.0.2";
	std::string loc_v = "312";
	int clients = 0;
	
	// Not yet implemented in profile
	std::vector<std::string> servers_v = {""};
	std::vector<std::string> consumers_v = {""};

	xapp_main_inst->generate_profile(instance_id_v, instance_name_v, instance_status_v, func_v, addresses, loc_v, clients);
	xapp_main_inst->display_profile();
	std::string xrfaddress_reg_endpoint = "http://127.0.0.1:9090/xapp/disc/0001";
	
	spdlog::info("xApp Profile Created");
	//---------------------------------------------------------------------------
	
	//--------------------------Send Authentication Challenge--------------------
	const std::string xrfaddress_auth_endpoint = "http://127.0.0.1:9090/init/auth";
	const std::string xrfchallenge = "Sudip's String A" ;
	spdlog::info("Sending Initial Authentication Challenge to XRF");
	xapp_main_inst->sendauth_to_xrf(xrfchallenge, xrfaddress_auth_endpoint);
	spdlog::info("Completed Initial Authentication with XRF");	
	//---------------------------------------------------------------------------
	
	//--------------------------XRF Registration---------------------------------
        xapp_main_inst->register_with_xrf(xrfaddress_reg_endpoint);
        //---------------------------------------------------------------------------

	
	//--------------------------xApp Discovery Request---------------------------
	std::string xrfaddress_disc_endpoint = "http://127.0.0.1:9090/xapp/discall";
	const std::string targetxApp = "TS";
	const std::string targetLoc = "312";
        xapp_main_inst->send_discovery_request(xrfaddress_disc_endpoint, targetxApp, targetLoc);
	//---------------------------------------------------------------------------


	//-------------------------OAuth 2.0 Token Request---------------------------
	const std::string xrfaddress_tokenreq_endpoint = "http://127.0.0.1:9090/oauth2/token";
	xapp_main_inst->send_token_req(xrfaddress_tokenreq_endpoint);
	//---------------------------------------------------------------------------

	//------------------------Starting service API-------------------------------
	spdlog::info("Starting Service API");
        Pistache::Address addr(Pistache::Ipv4::any(), Pistache::Port(9095));
        api_server = new XRFcApiServer(addr, xapp_main_inst);
        api_server->init(2);
        //std::thread xrf_manager(&XRFApiServer::start, api_server);
        api_server->start();

	//---------------------------------------------------------------------------


	return 0;
}



