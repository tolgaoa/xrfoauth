#include "xrf_jwt.hpp"
#include "xrf_main.hpp"
#include "xrf-api-server.h"

#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>  
#include <unistd.h>  
#include <iostream>
#include <thread>

using namespace xrf::app;
using namespace Pistache;

xrf_main* xrf_main_inst = nullptr;
XRFApiServer* api_server = nullptr;

const char *nc = "CLIENT_COUNT";

int main(int argc, char** argv){
	
	spdlog::set_level(spdlog::level::debug);

	spdlog::info("Starting XRF API Server");
	Pistache::Address addr(Pistache::Ipv4::any(), Pistache::Port(9090));
	api_server = new XRFApiServer(addr, xrf_main_inst);	
	api_server->init(2);
	//std::thread xrf_manager(&XRFApiServer::start, api_server);
	api_server->start();

	return 0;


}
