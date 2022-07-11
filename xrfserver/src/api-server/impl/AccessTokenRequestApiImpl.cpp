/**
* XRF OAuth2
* XRF OAuth2 Authorization server for generating access tokens to xApps 
*
* The version of the OpenAPI document: 1
* Contact: tolgaoa@vt.edu
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/

#include "AccessTokenRequestApiImpl.h"
#include "AccessTokenRsp.h"

namespace xrf::api {

using namespace xrf::model;
using namespace xrf::app;

const char *nc = "CLIENT_COUNT";
auto wbegin = std::chrono::high_resolution_clock::now();
auto wend = std::chrono::high_resolution_clock::now();

clock_t cstart = clock();
clock_t cend = clock();
int inc;

AccessTokenRequestApiImpl::AccessTokenRequestApiImpl(
		std::shared_ptr<Pistache::Rest::Router>& rtr, xrf_main* xrf_main_inst, 
		std::string addr)
    		: AccessTokenRequestApi(rtr), m_xrf_main(xrf_main_inst), m_addr(addr) {
			pclient_c = 0;
			//Get expected client count
			const char *tmp = getenv("CLIENT_COUNT");
			std::string nc(tmp ? tmp : "");
			if (nc.empty()) {
				spdlog::error("client count not found");
				exit(EXIT_FAILURE);
			}
			spdlog::debug("Expected client count is: {}", nc);
			std::string ncs = nc;
			inc = std::stoi(ncs);
		}

void AccessTokenRequestApiImpl::access_token_request(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter &response){	
	spdlog::info("Incoming Request for an OAuth2 access token from xApp");	
	int http_code = 0;
	ProblemDetails problem_details = {};
	AccessTokenRsp access_token_rsp = {};
	m_xrf_main->access_token_request(request.body(), access_token_rsp, http_code, 1, problem_details);
	spdlog::info("Token generation complete");
	nlohmann::json json_data = {};
	std::string content_type = "application/problem+json";

	if (http_code != 200) { //check if HTTP_STATUS_CODE is 200
		to_json(json_data, problem_details);
		content_type = "application/problem+json";
	} else to_json(json_data, access_token_rsp);
	
	response.headers().add<Pistache::Http::Header::ContentType>(Pistache::Http::Mime::MediaType(content_type));
	response.send(Pistache::Http::Code(http_code), json_data.dump().c_str());
	pclient_c++;
	
	if (pclient_c == 1) wbegin = std::chrono::high_resolution_clock::now(); //Start server wall clock
	if (pclient_c == 1) cstart = clock(); // Start server cpu clock

	if (pclient_c == inc) {
		cend = clock(); // Stop server cpu clock
		wend = std::chrono::high_resolution_clock::now(); //Stop server wall clock 
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

	}
}

}
