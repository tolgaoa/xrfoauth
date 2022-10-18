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
const char *IPC_VAR = "SERVER_CLIENT";
const char *PORT_VAR = "XRF_PORT";
const char *PORTC_VAR = "CLIENT_PORT";
const char *REG_VAR = "REG_COUNT";


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


void callInitAuth(std::string http_pre, std::string ip_var, std::string port_var) {

        //--------------------------Send Authentication Challenge--------------------
        auto wbegin = std::chrono::high_resolution_clock::now();
        clock_t cstart = clock();
	const std::string xrfaddress_auth_endpoint = http_pre + ip_var + ":" + port_var + "/init/auth";
        const std::string xrfchallenge = "Sudip's String A" ;
        spdlog::info("Sending Initial Authentication Challenge to XRF");
        xapp_main_inst->sendauth_to_xrf(xrfchallenge, xrfaddress_auth_endpoint);
        spdlog::info("Completed Initial Authentication with XRF");
	clock_t cend = clock(); // Stop client cpu clock
        auto wend = std::chrono::high_resolution_clock::now(); //Stop client wall clock
        //---------------------------------------------------------------------------
        double celapsed = double(cend - cstart)/CLOCKS_PER_SEC; // calculate cpu time
        spdlog::debug("CPU-time: {} ms", celapsed * 1000.0);
        auto welapsed = std::chrono::duration<double, std::milli>(wend - wbegin); //calculate wall time
        spdlog::debug("Wall-time: {} ms", welapsed.count());

        auto celapseds = std::to_string(celapsed*1000.0);
        auto welapseds = std::to_string(welapsed.count());

        std::ofstream out("latencyauth.txt");
        out << celapseds;
        out << "\n";
        out << welapseds;
        out << "\n";
        out.close();
};

void callReg(std::string http_pre, std::string ip_var, std::string port_var, int count) {
        //--------------------------XRF Registration---------------------------------
        auto wbegin = std::chrono::high_resolution_clock::now();
        clock_t cstart = clock();
        //std::string xrfaddress_reg_endpoint = "http://127.0.0.1:9090/xapp/disc/0001";
        std::string xrfaddress_reg_endpoint = http_pre + ip_var + ":" + port_var + "/xapp/disc/0001";
	for (int i = 0; i < count; i++) {
        	xapp_main_inst->register_with_xrf(xrfaddress_reg_endpoint);
	}
	clock_t cend = clock(); // Stop client cpu clock
        auto wend = std::chrono::high_resolution_clock::now(); //Stop client wall clock
        //---------------------------------------------------------------------------
        double celapsed = double(cend - cstart)/CLOCKS_PER_SEC; // calculate cpu time
        spdlog::debug("CPU-time: {} ms", celapsed * 1000.0);
        auto welapsed = std::chrono::duration<double, std::milli>(wend - wbegin); //calculate wall time
        spdlog::debug("Wall-time: {} ms", welapsed.count());

        auto celapseds = std::to_string(celapsed*1000.0);
        auto welapseds = std::to_string(welapsed.count());

        std::ofstream out("latencyreg.txt");
        out << celapseds;
        out << "\n";
        out << welapseds;
        out << "\n";
        out.close();
};

void callDisc(std::string http_pre, std::string ip_var, std::string port_var) {
        //--------------------------xApp Discovery Request---------------------------
        auto wbegin = std::chrono::high_resolution_clock::now();
        clock_t cstart = clock();
        //std::string xrfaddress_disc_endpoint = "http://127.0.0.1:9090/xapp/discall";
        std::string xrfaddress_disc_endpoint = http_pre + ip_var + ":" + port_var + "/xapp/discall";
        const std::string targetxApp = "TS";
        const std::string targetLoc = "312";
        xapp_main_inst->send_discovery_request(xrfaddress_disc_endpoint, targetxApp, targetLoc);
	clock_t cend = clock(); // Stop client cpu clock
        auto wend = std::chrono::high_resolution_clock::now(); //Stop client wall clock
        //---------------------------------------------------------------------------
        double celapsed = double(cend - cstart)/CLOCKS_PER_SEC; // calculate cpu time
        spdlog::debug("CPU-time: {} ms", celapsed * 1000.0);
        auto welapsed = std::chrono::duration<double, std::milli>(wend - wbegin); //calculate wall time
        spdlog::debug("Wall-time: {} ms", welapsed.count());

        auto celapseds = std::to_string(celapsed*1000.0);
        auto welapseds = std::to_string(welapsed.count());

        std::ofstream out("latencydisc.txt");
        out << celapseds;
        out << "\n";
        out << welapseds;
        out << "\n";
        out.close();

};

void callTokenReq(std::string http_pre, std::string ip_var, std::string port_var) {
        //-------------------------OAuth 2.0 Token Request---------------------------
        auto wbegin = std::chrono::high_resolution_clock::now();
        clock_t cstart = clock();
        const std::string xrfaddress_tokenreq_endpoint = http_pre + ip_var + ":" + port_var + "/oauth2/token";
        xapp_main_inst->send_token_req(xrfaddress_tokenreq_endpoint);
        auto wend = std::chrono::high_resolution_clock::now(); //Stop client wall clock
	clock_t cend = clock(); // Stop client cpu clock
        //---------------------------------------------------------------------------
        double celapsed = double(cend - cstart)/CLOCKS_PER_SEC; // calculate cpu time
        spdlog::debug("CPU-time: {} ms", celapsed * 1000.0);
        auto welapsed = std::chrono::duration<double, std::milli>(wend - wbegin); //calculate wall time
        spdlog::debug("Wall-time: {} ms", welapsed.count());

        auto celapseds = std::to_string(celapsed*1000.0);
        auto welapseds = std::to_string(welapsed.count());

        std::ofstream out("latencytoken.txt");
        out << celapseds;
        out << "\n";
        out << welapseds;
        out << "\n";
        out.close();
};

void callClientConnReq(std::string http_pre, std::string ipc_var, std::string portc_var) {

        auto wbegincl = std::chrono::high_resolution_clock::now(); // Start client wall clock for connection request
        clock_t cstartcl = clock(); // Start client cpu clock for connection request
        for (int i = 0; i < 10; i++) {
                const std::string xrfclientaddress_connreq_endpoint = http_pre + ipc_var + ":" + portc_var + "/serv/test";
                xapp_main_inst->send_client_connection(xrfclientaddress_connreq_endpoint);
        }
        clock_t cendcl = clock(); // Stop client cpu clock
        auto wendcl = std::chrono::high_resolution_clock::now(); //Stop client wall clock
        double celapsedcl = double(cendcl - cstartcl)/CLOCKS_PER_SEC; // calculate cpu time
        spdlog::debug("CPU-time: {} ms", celapsedcl * 1000.0);
        auto welapsedcl = std::chrono::duration<double, std::milli>(wendcl - wbegincl); //calculate wall time
        spdlog::debug("Wall-time: {} ms", welapsedcl.count());

        auto celapsedscl = std::to_string(celapsedcl*1000.0);
        auto welapsedscl = std::to_string(welapsedcl.count());

        std::ofstream out1("cllatency.txt");
        out1 << celapsedscl;
        out1 << "\n";
        out1 << welapsedscl;
        out1 << "\n";
        out1.close();
};

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

        //Get Client IP
        const char *tmp3 = getenv("SERVER_CLIENT");
        string ipc_var(tmp3 ? tmp3 : "");
        if (ipc_var.empty()) {
                spdlog::error("Client address not found");
                exit(EXIT_FAILURE);
        }
        spdlog::info("Client Server port is: {}", port_var);

        //Get Client Port
        const char *tmp4 = getenv("CLIENT_PORT");
        string portc_var(tmp4 ? tmp4 : "");
        if (portc_var.empty()) {
                spdlog::error("Client Port not found");
                exit(EXIT_FAILURE);
        }
        spdlog::info("Client Server port is: {}", port_var);

        //Get Reg Count
        const char *tmp5 = getenv("REG_COUNT");
        string reg_var(tmp5 ? tmp5 : "");
        if (reg_var.empty()) {
                spdlog::error("Registration count not found");
                exit(EXIT_FAILURE);
        }
        spdlog::info("Registration count is: {}", reg_var);

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

	int countReg = std::stoi(reg_var);

	callInitAuth(http_pre, ip_var, port_var);
	callReg(http_pre, ip_var, port_var, countReg);	
	callDisc(http_pre, ip_var, port_var);
	callTokenReq(http_pre, ip_var, port_var);

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
	
	//---------------------------Client Connection Request-----------------------
	
	//callClientConnReq(http_pre, ipc_var, portc_var);        

	//------------------------Starting service API-------------------------------
	spdlog::info("Starting Service API");
        Pistache::Address addr(Pistache::Ipv4::any(), Pistache::Port(9095));
        api_server = new XRFcApiServer(addr, xapp_main_inst);
        api_server->init(4);
        api_server->start();
	//---------------------------------------------------------------------------
	return 0;
}



