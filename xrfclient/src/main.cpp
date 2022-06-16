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

	const std::string xrfaddress = "http://172.17.0.2:9090/init/auth";

	//---------------------------Create xApp Profile-----------------------------	
	spdlog::info("Creating xApp Profile");
        std::string instance_id_v = "xAppUUIDCreate";
        std::string instance_name_v = "testxApp1";
        std::string instance_status_v = "Initial Spawn";
        std::string func_v = "TS";
	std::vector<string> addresses = {"172.17.0.2"};
	
	xapp_main_inst->generate_profile(instance_id_v, instance_name_v, instance_status_v, func_v, addresses);
	xapp_main_inst->display_profile();
	spdlog::info("xApp Profile Created");
	//---------------------------------------------------------------------------

	//--------------------------Send Authentication Challenge--------------------
	spdlog::info("Sending Initial Authentication Challenge to XRF");
	const std::string xrfchallenge = "Sudip's String A" ;
	xapp_main_inst->sendauth_to_xrf(xrfchallenge, xrfaddress);
	spdlog::info("Completed Initial Authentication with XRF");	
	//---------------------------------------------------------------------------
	
	return 0;
}



