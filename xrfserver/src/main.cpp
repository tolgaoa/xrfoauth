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
const char *tc = "THREAD_COUNT";

auto wbeginor = std::chrono::high_resolution_clock::now();

void reportTime(std::shared_mutex *mtx_start, std::shared_mutex *mtx_end) {

	mtx_start->lock();
	auto wstart = std::chrono::high_resolution_clock::now(); // Start client wall clock
	clock_t cstart = clock(); // Start client cpu clock

	mtx_end->lock();
        clock_t cend = clock(); // Stop client cpu clock
        auto wend = std::chrono::high_resolution_clock::now(); //Stop client wall clock
        double celapsed = double(cend - cstart)/CLOCKS_PER_SEC; // calculate cpu time
        spdlog::debug("CPU-time: {} ms", celapsed * 1000.0);
        auto welapsed = std::chrono::duration<double, std::milli>(wend - wstart); //calculate wall time
        spdlog::debug("Wall-time: {} ms", welapsed.count());

        auto celapseds = std::to_string(celapsed*1000.0);
        auto welapseds = std::to_string(welapsed.count());

}

void clientStarted(std::shared_mutex *mtx_start) {
	mtx_start->unlock();
}

void clientEnded(std::shared_mutex *mtx_end, int *clientc) {

	*clientc++;
	
	//Get expected client count
	const char *tmp = getenv("CLIENT_COUNT");
	std::string nc(tmp ? tmp : "");
	if (nc.empty()) {
		spdlog::error("client count not found");
		exit(EXIT_FAILURE);
	}
	spdlog::debug("Expected client count is: {}", nc);
	std::string ncs = nc;
	int inc = std::stoi(ncs); 

	if (*clientc == inc) {
        	mtx_end->unlock();
	}
	
}


int main(int argc, char** argv){
	
	
	spdlog::set_level(spdlog::level::debug);
	
        //Get Thread count
        const char *tmp = getenv("THREAD_COUNT");
	std::string tc(tmp ? tmp : "");
        if (tc.empty()) {
                spdlog::error("Thread count not found");
                exit(EXIT_FAILURE);
        }
        spdlog::info("Thread count is: {}", tc);

	std::stringstream sstc(tc);
	size_t tcr;
	sstc >> tcr;

	int clientc = 0;

	std::shared_mutex mutex_start, mutex_end;
	mutex_start.lock();
	mutex_end.lock();

	spdlog::info("Starting XRF API Server");
	Pistache::Address addr(Pistache::Ipv4::any(), Pistache::Port(9090));
	api_server = new XRFApiServer(addr, xrf_main_inst);	
	api_server->init(tcr);
	api_server->start();

	return 0;


}
