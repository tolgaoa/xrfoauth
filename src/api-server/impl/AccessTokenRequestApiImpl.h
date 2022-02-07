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

/*
* AccessTokenRequestApiImpl.h
*
* 
*/

#ifndef ACCESS_TOKEN_REQUEST_API_IMPL_H_
#define ACCESS_TOKEN_REQUEST_API_IMPL_H_


#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/router.h>
#include <memory>

#include <AccessTokenRequestApi.h>

//#include <pistache/optional.h>

#include "ProblemDetails.h"
#include "AccessTokenErr.h"
#include "AccessTokenRsp.h"
#include <string>

#include "xrf_main.hpp"

namespace xrf::api
{

using namespace xrf::model;
using namespace xrf::app;

class AccessTokenRequestApiImpl : public xrf::api::AccessTokenRequestApi {
public:
	AccessTokenRequestApiImpl(std::shared_ptr<Pistache::Rest::Router>& rtr, xrf_main* xrf_main_inst,
		               std::string addr);
	~AccessTokenRequestApiImpl() {}

	void access_token_request(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter &response);
private:
	xrf_main*  m_xrf_main;
	std::string m_addr;

};

} 

#endif
