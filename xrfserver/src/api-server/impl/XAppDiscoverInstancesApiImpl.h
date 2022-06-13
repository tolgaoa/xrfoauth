/**
* XRF OAuth2 xApp Discvoery API
* XRF OAuth2 Authorization server, xApp Discovery API 
*
* The version of the OpenAPI document: 1
* Contact: tolgaoa@vt.edu
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/

/*
* XAppDiscoverInstancesApiImpl.h
*
* 
*/

#ifndef X_APP_DISCOVER_INSTANCES_API_IMPL_H_
#define X_APP_DISCOVER_INSTANCES_API_IMPL_H_


#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/router.h>
#include <memory>

#include <XAppDiscoverInstancesApi.h>

#include <pistache/optional.h>

#include "XAppDiscErr.h"
#include "XAppDiscRsp.h"
#include "XAppService.h"

namespace xrf::api
{

using namespace xrf::model;

class XAppDiscoverInstancesApiImpl : public xrf::api::XAppDiscoverInstancesApi {
public:
    explicit XAppDiscoverInstancesApiImpl(const std::shared_ptr<Pistache::Rest::Router>& rtr);
    ~XAppDiscoverInstancesApiImpl() override = default;

    void x_app_disc_inst(const Pistache::Optional<XAppService> &targetxApp, Pistache::Http::ResponseWriter &response);

};

} // namespace xrf::api



#endif
