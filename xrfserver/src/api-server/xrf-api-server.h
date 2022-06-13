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

#include "AccessTokenRequestApiImpl.h"
#include "InitialAuthenticationRequestApiImpl.h"
#include "XAppRegisterInstanceApiImpl.h"
#include "xrf_main.hpp"

using namespace xrf::api;
using namespace xrf::app;
class XRFApiServer {
public:
	XRFApiServer(Pistache::Address address, xrf_main* xrf_main_inst) 
        	: m_httpEndpoint(std::make_shared<Pistache::Http::Endpoint>(address)) {
		
		m_router  = std::make_shared<Pistache::Rest::Router>();
        	m_address = address.host() + ":" + (address.port()).toString();

        	m_accessTokenRequestApiImpl = std::make_shared<AccessTokenRequestApiImpl>(
            		m_router, xrf_main_inst, m_address);

       	 	m_initialAuthenticationRequestApiImpl = std::make_shared<InitialAuthenticationRequestApiImpl>(
            		m_router, xrf_main_inst, m_address);

                m_XAppRegisterInstanceApiImpl = std::make_shared<XAppRegisterInstanceApiImpl>(
                        m_router, xrf_main_inst, m_address);
	
	}		
	void init(size_t thr = 1);
	void start();
	void shutdown();

private:
	// Pointers to Pistache endpoint and router
	std::shared_ptr<Pistache::Http::Endpoint> m_httpEndpoint;
	std::shared_ptr<Pistache::Rest::Router> m_router;
	
	// Pointers to Individual endpoint handlers
	std::shared_ptr<AccessTokenRequestApiImpl> m_accessTokenRequestApiImpl;
	std::shared_ptr<InitialAuthenticationRequestApiImpl> m_initialAuthenticationRequestApiImpl;
	std::shared_ptr<XAppRegisterInstanceApiImpl> m_XAppRegisterInstanceApiImpl;

	// String address
	std::string m_address;
};

#endif
