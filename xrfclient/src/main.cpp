#include "xapp_main.hpp"
#include "xrf_client.hpp"

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

	const std::string xrfaddress = "http://192.168.3.149:9090/init/auth";
	const std::string xrfchallenge = "Sudip's String A" ;
	spdlog::info("Sending Initial Authentication Challenge to XRF");
	xapp_main_inst->sendauth_to_xrf(xrfchallenge, xrfaddress);
	spdlog::info("Completed Initial Authentication with XRF");	
	
	return 0;
}



