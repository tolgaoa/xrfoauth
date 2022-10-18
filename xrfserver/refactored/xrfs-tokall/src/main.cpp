/*
 * Re-factoring of the XRF code by separating the registration module
 *
 * ! file main.cpp
 *  \brief
 * \author: Tolga Atalay 
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/router.h>

#include "rapidjson/document.h"

#include <iostream>
#include "spdlog/spdlog.h"

#include "handlers.hpp"

using namespace Pistache;
using namespace xrf::app;

void handlereq(const Rest::Request& req, Http::ResponseWriter resp){


        spdlog::debug("Receiving Token request credentials: {}", req.body());
	std::string response_send;
	handlers handler1;
	int http_code;
	
	
	handler1.access_token_request(req.body(), response_send, http_code, 1);
        resp.send(Pistache::Http::Code::Ok, response_send);

}

void handlejwks(const Rest::Request& req, Http::ResponseWriter resp){


        spdlog::debug("Receiving Token JWKS credentials: {}", req.body());
        std::string response_send;
        handlers handler2;
        int http_code;


        handler2.fetch_token_key(req.body(), response_send);
        resp.send(Pistache::Http::Code::Ok, response_send);

}

void handleremoteintro(const Rest::Request& req, Http::ResponseWriter resp){


        spdlog::debug("Receiving Remote Token Credentials", req.body());
        std::string response_send;
        handlers handler3;
        int http_code;


        handler3.validate_token(req.body(), response_send);
        resp.send(Pistache::Http::Code::Ok, response_send);

}


int main(int argc, char* argv[])
{
	spdlog::set_level(spdlog::level::debug);
	using namespace Rest;

	Router router;
	Port port(9999);
	Address addr(Ipv4::any(), port);
	std::shared_ptr<Http::Endpoint> endpoint = std::make_shared<Http::Endpoint>(addr);
	auto opts = Http::Endpoint::options().threads(2);
	opts.flags(Pistache::Tcp::Options::ReuseAddr);
	endpoint->init(opts);

	Routes::Post(router, "/xrftokreqext", Routes::bind(handlereq));
	Routes::Post(router, "/xrftokintroext", Routes::bind(handleremoteintro));
	Routes::Post(router, "/xrftokjwksext", Routes::bind(handlejwks));

	spdlog::info("Starting HTTP Server for XRF-General Token Handler");
	endpoint->setHandler(router.handler());
	endpoint->serve();
}
