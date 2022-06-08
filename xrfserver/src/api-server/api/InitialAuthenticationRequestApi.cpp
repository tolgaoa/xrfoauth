/**
* XRF OAuth2 Initial Authentication Request API
* XRF OAuth2 Authorization server, initial authentication with the xApp API 
*
* The version of the OpenAPI document: 1
* Contact: tolgaoa@vt.edu
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/

#include "InitialAuthenticationRequestApi.h"
#include "Helpers.h"

namespace xrf::api
{

using namespace xrf::helpers;
using namespace xrf::model;

const std::string InitialAuthenticationRequestApi::base = "";

InitialAuthenticationRequestApi::InitialAuthenticationRequestApi(const std::shared_ptr<Pistache::Rest::Router>& rtr)
    : router(rtr)
{}

void InitialAuthenticationRequestApi::init() {
    setupRoutes();
}

void InitialAuthenticationRequestApi::setupRoutes() {
    using namespace Pistache::Rest;

    Routes::Post(*router, base + "/init/auth", Routes::bind(&InitialAuthenticationRequestApi::init_auth_request_handler, this));

    // Default handler, called when a route is not found
    router->addCustomHandler(Routes::bind(&InitialAuthenticationRequestApi::initial_authentication_request_api_default_handler, this));
}

std::pair<Pistache::Http::Code, std::string> InitialAuthenticationRequestApi::handleParsingException(const std::exception& ex) const noexcept
{
    try {
        throw;
    } catch (nlohmann::detail::exception &e) {
        return std::make_pair(Pistache::Http::Code::Bad_Request, e.what());
    } catch (xrf::helpers::ValidationException &e) {
        return std::make_pair(Pistache::Http::Code::Bad_Request, e.what());
    } catch (std::exception &e) {
        return std::make_pair(Pistache::Http::Code::Internal_Server_Error, e.what());
    }
}

std::pair<Pistache::Http::Code, std::string> InitialAuthenticationRequestApi::handleOperationException(const std::exception& ex) const noexcept
{
    return std::make_pair(Pistache::Http::Code::Internal_Server_Error, ex.what());
}

void InitialAuthenticationRequestApi::init_auth_request_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response) {
    try {
    
    InitAuthReq initAuthReq;
    
    try {
        nlohmann::json::parse(request.body()).get_to(initAuthReq);
        initAuthReq.validate();
    } catch (std::exception &e) {
        const std::pair<Pistache::Http::Code, std::string> errorInfo = this->handleParsingException(e);
        response.send(errorInfo.first, errorInfo.second);
        return;
    }

    try {
        this->init_auth_request(request, response);
    } catch (Pistache::Http::HttpError &e) {
        response.send(static_cast<Pistache::Http::Code>(e.code()), e.what());
        return;
    } catch (std::exception &e) {
        const std::pair<Pistache::Http::Code, std::string> errorInfo = this->handleOperationException(e);
        response.send(errorInfo.first, errorInfo.second);
        return;
    }

    } catch (std::exception &e) {
        response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
    }

}

void InitialAuthenticationRequestApi::initial_authentication_request_api_default_handler(const Pistache::Rest::Request &, Pistache::Http::ResponseWriter response) {
    response.send(Pistache::Http::Code::Not_Found, "The requested method does not exist");
}
  

} // namespace xrf::api

