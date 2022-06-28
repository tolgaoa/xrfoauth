#ifndef FILE_NRF_API_SERVER_SEEN
#define FILE_NRF_API_SERVER_SEEN

#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"
#ifdef __linux__
#include <vector>
#include <signal.h>
#include <unistd.h>
#endif

#include "ServiceTestRequestApiImpl.h"
#include "xapp_main.hpp"

using namespace xrf::api;
using namespace xrf::app;
class XRFcApiServer {
public:
	XRFcApiServer(Pistache::Address address, xapp_main* xapp_main_inst) 
        	: m_httpEndpoint(std::make_shared<Pistache::Http::Endpoint>(address)) {
		
		m_router  = std::make_shared<Pistache::Rest::Router>();
        	m_address = address.host() + ":" + (address.port()).toString();

        	m_ServiceTestRequestApiImpl = std::make_shared<ServiceTestRequestApiImpl>(
            		m_router, xapp_main_inst, m_address);

	}		
	void init(size_t thr = 4);
	void start();
	void shutdown();

private:
	// Pointers to Pistache endpoint and router
	std::shared_ptr<Pistache::Http::Endpoint> m_httpEndpoint;
	std::shared_ptr<Pistache::Rest::Router> m_router;
	
	// Pointers to Individual endpoint handlers
	std::shared_ptr<ServiceTestRequestApiImpl> m_ServiceTestRequestApiImpl;

	// String address
	std::string m_address;
};

#endif
