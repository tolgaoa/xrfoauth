#include "xapp_main.hpp"
#include "xrf_client.hpp"
#include "xapp_profile.hpp"

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <thread>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using namespace xrf::app;

xapp_main* xapp_main_inst = nullptr;

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

	xapp_main_inst->generate_profile(instance_id_v, instance_name_v, instance_status_v, func_v, addresses);
	xapp_main_inst->display_profile();
	std::string xrfaddress_reg_endpoint = "http://10.0.0.135:9090/xapp/disc/0001";
	
	spdlog::info("xApp Profile Created");
	//---------------------------------------------------------------------------
	
	//--------------------------Send Authentication Challenge--------------------
	const std::string xrfaddress_auth_endpoint = "http://10.0.0.135:9090/init/auth";
	const std::string xrfchallenge = "Sudip's String A" ;
	spdlog::info("Sending Initial Authentication Challenge to XRF");
	xapp_main_inst->sendauth_to_xrf(xrfchallenge, xrfaddress_auth_endpoint);
	spdlog::info("Completed Initial Authentication with XRF");	
	//---------------------------------------------------------------------------
	
	//--------------------------XRF Registration---------------------------------
        xapp_main_inst->register_with_xrf(xrfaddress_reg_endpoint);
        //---------------------------------------------------------------------------

	return 0;
}



