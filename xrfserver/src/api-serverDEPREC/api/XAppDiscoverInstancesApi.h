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
 * XAppDiscoverInstancesApi.h
 *
 * 
 */

#ifndef XAppDiscoverInstancesApi_H_
#define XAppDiscoverInstancesApi_H_


#include <pistache/http.h>
#include <pistache/router.h>
#include <pistache/http_headers.h>
#include <pistacheDep/optional.h>

#include <utility>

#include "XAppDiscErr.h"
#include "XAppDiscRsp.h"
#include "XAppService.h"

namespace xrf::api
{

class  XAppDiscoverInstancesApi {
public:
    explicit XAppDiscoverInstancesApi(const std::shared_ptr<Pistache::Rest::Router>& rtr);
    virtual ~XAppDiscoverInstancesApi() = default;
    void init();

    static const std::string base;

private:
    void setupRoutes();

    void x_app_disc_inst_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response);
    void x_app_discover_instances_api_default_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response);

    const std::shared_ptr<Pistache::Rest::Router> router;

    /// <summary>
    /// Helper function to handle unexpected Exceptions during Parameter parsing and validation.
    /// May be overridden to return custom error formats. This is called inside a catch block.
    /// Important: When overriding, do not call `throw ex;`, but instead use `throw;`.
    /// </summary>
    virtual std::pair<Pistache::Http::Code, std::string> handleParsingException(const std::exception& ex) const noexcept;

    /// <summary>
    /// Helper function to handle unexpected Exceptions during processing of the request in handler functions.
    /// May be overridden to return custom error formats. This is called inside a catch block.
    /// Important: When overriding, do not call `throw ex;`, but instead use `throw;`.
    /// </summary>
    virtual std::pair<Pistache::Http::Code, std::string> handleOperationException(const std::exception& ex) const noexcept;

    /// <summary>
    /// Discover the set of xApp Instances offering a given service
    /// </summary>
    /// <remarks>
    /// 
    /// </remarks>
    /// <param name="targetxApp">service offered by the target xApp (optional, default to std::make_shared&lt;XAppService&gt;())</param>
    virtual void x_app_disc_inst(const xrf::model::Pistache::Optional<XAppService> &targetxApp, Pistache::Http::ResponseWriter &response) = 0;

};

} // namespace xrf::api

#endif /* XAppDiscoverInstancesApi_H_ */

