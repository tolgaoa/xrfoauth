#include "xrf_jwt.hpp"
#include "xrf_main.hpp"
#include "xrf-api-server.h"

#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>  // srand
#include <unistd.h>  // get_pid(), pause()
#include <iostream>
#include <thread>


using namespace xrf::app;
using namespace Pistache;

xrf_main* xrf_main_inst = nullptr;
XRFApiServer* api_server = nullptr;

class HelloHandler : public Http::Handler
{
public:
    HTTP_PROTOTYPE(HelloHandler)

    void onRequest(const Http::Request& /*request*/, Http::ResponseWriter response) override
    {
        response.send(Pistache::Http::Code::Ok, "Hello World\n");
    }
};

int main(int argc, char** argv){

	//Test JWT
	xrf_jwt obj;
	obj.test_jwt();

	//Define the XRF application instance pointer

	//Test Sample Pistache Server
	Pistache::Address addr(Pistache::Ipv4::any(), Pistache::Port(9080));
	auto opts = Pistache::Http::Endpoint::options()
		    .threads(1);

	Http::Endpoint server(addr);
	server.init(opts);
	server.setHandler(Http::make_handler<HelloHandler>());
	server.serve();	
	
	//api_server = new XRFApiServer(addr, xrf_main_inst);
	//api_server->init(2);

	return 0;


}
