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

#include "InitialAuthenticationRequestApiImpl.h"

namespace org {
namespace openapitools {
namespace server {
namespace api {

using namespace org::openapitools::server::model;

InitialAuthenticationRequestApiImpl::InitialAuthenticationRequestApiImpl(const std::shared_ptr<Pistache::Rest::Router>& rtr)
    : InitialAuthenticationRequestApi(rtr)
{
}

void InitialAuthenticationRequestApiImpl::init_auth_request(const InitAuthReq &initAuthReq, Pistache::Http::ResponseWriter &response) {
    response.send(Pistache::Http::Code::Ok, "Do some magic\n");
}

}
}
}
}

