#include "xapp_main.hpp"
#include "xrf_client.hpp"
#include "xapp_profile.hpp"
#include "xrfc-api-server.h"

#include <stdio.h>
#include <chrono>
#include <fstream>
#include <string_view>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <curl/curl.h>
#include <nlohmann/json.hpp>


using namespace xrf::app;
using namespace Pistache;

xapp_main* xapp_main_inst = nullptr;
XRFcApiServer* api_server = nullptr;

const char *IP_VAR = "SERVER_XRF";
const char *PORT_VAR = "XRF_PORT";


template <typename T>
constexpr auto type_name() {
  std::string_view name, prefix, suffix;
#ifdef __clang__
  name = __PRETTY_FUNCTION__;
  prefix = "auto type_name() [T = ";
  suffix = "]";
#elif defined(__GNUC__)
  name = __PRETTY_FUNCTION__;
  prefix = "constexpr auto type_name() [with T = ";
  suffix = "]";
#elif defined(_MSC_VER)
  name = __FUNCSIG__;
  prefix = "auto __cdecl type_name<";
  suffix = ">(void)";
#endif
  name.remove_prefix(prefix.size());
  name.remove_suffix(suffix.size());
  return name;
}

int main(int argc, char** argv){

        //Set log level debug
        spdlog::set_level(spdlog::level::debug);

	auto wbegin = std::chrono::high_resolution_clock::now(); // Start client wall clock
	clock_t cstart = clock(); // Start client cpu clock


	//Get Server IP
	const char *tmp = getenv("SERVER_XRF");
	string ip_var(tmp ? tmp : "");
	if (ip_var.empty()) {
		spdlog::error("Server IP not found");
		exit(EXIT_FAILURE);
	}
	spdlog::info("XRF Server reachable at: {}", ip_var);
	std::string http_pre = "http://";

        //Get Server Port
        const char *tmp2 = getenv("XRF_PORT");
        string port_var(tmp2 ? tmp2 : "");
        if (port_var.empty()) {
                spdlog::error("Server Port not found");
                exit(EXIT_FAILURE);
        }
        spdlog::info("XRF Server port is: {}", port_var);


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
	
	spdlog::info("xApp Profile Created");
	//---------------------------------------------------------------------------
	
	//--------------------------Send Authentication Challenge--------------------
	//const std::string xrfaddress_auth_endpoint = "http://127.0.0.1:9090/init/auth";
        const std::string xrfaddress_auth_endpoint = http_pre + ip_var + ":" + port_var + "/init/auth";
	const std::string xrfchallenge = "Sudip's String A" ;
	spdlog::info("Sending Initial Authentication Challenge to XRF");
	xapp_main_inst->sendauth_to_xrf(xrfchallenge, xrfaddress_auth_endpoint);
	spdlog::info("Completed Initial Authentication with XRF");	
	//---------------------------------------------------------------------------
	
	//--------------------------XRF Registration---------------------------------
        //std::string xrfaddress_reg_endpoint = "http://127.0.0.1:9090/xapp/disc/0001";
        std::string xrfaddress_reg_endpoint = http_pre + ip_var + ":" + port_var + "/xapp/disc/0001";
        xapp_main_inst->register_with_xrf(xrfaddress_reg_endpoint);
        //---------------------------------------------------------------------------

	
	//--------------------------xApp Discovery Request---------------------------
	//std::string xrfaddress_disc_endpoint = "http://127.0.0.1:9090/xapp/discall";
        std::string xrfaddress_disc_endpoint = http_pre + ip_var + ":" + port_var + "/xapp/discall";
	const std::string targetxApp = "TS";
	const std::string targetLoc = "312";
        xapp_main_inst->send_discovery_request(xrfaddress_disc_endpoint, targetxApp, targetLoc);
	//---------------------------------------------------------------------------


	//-------------------------OAuth 2.0 Token Request---------------------------
	//const std::string xrfaddress_tokenreq_endpoint = "http://127.0.0.1:9090/oauth2/token";
        const std::string xrfaddress_tokenreq_endpoint = http_pre + ip_var + ":" + port_var + "/oauth2/token";
	xapp_main_inst->send_token_req(xrfaddress_tokenreq_endpoint);
	//---------------------------------------------------------------------------

	clock_t cend = clock(); // Stop client cpu clock
	auto wend = std::chrono::high_resolution_clock::now(); //Stop client wall clock
	double celapsed = double(cend - cstart)/CLOCKS_PER_SEC; // calculate cpu time
	spdlog::debug("CPU-time: {} ms", celapsed * 1000.0);
	auto welapsed = std::chrono::duration<double, std::milli>(wend - wbegin); //calculate wall time
	spdlog::debug("Wall-time: {} ms", welapsed.count());

	auto celapseds = std::to_string(celapsed*1000.0);
	auto welapseds = std::to_string(welapsed.count());

	std::ofstream out("latency.txt");
	out << celapseds;
	out << "\n";
	out << welapseds;
	out << "\n";
	out.close();
	
	//------------------------Starting service API-------------------------------
	spdlog::info("Starting Service API");
        Pistache::Address addr(Pistache::Ipv4::any(), Pistache::Port(9095));
        api_server = new XRFcApiServer(addr, xapp_main_inst);
        api_server->init(2);
        api_server->start();
	//---------------------------------------------------------------------------
	return 0;
}



