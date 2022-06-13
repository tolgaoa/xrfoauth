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
 * XAppRegisterInstanceApi.h
 *
 * 
 */

#ifndef XAppRegisterInstanceApi_H_
#define XAppRegisterInstanceApi_H_


#include <pistache/http.h>
#include <pistache/router.h>
#include <pistache/http_headers.h>
#include <pistache/optional.h>

#include <utility>
#include <iostream>

#include "XAppDiscErr.h"
#include "XAppProfile.h"
#include <string>
#include <vector>

#include "spdlog/spdlog.h"

namespace xrf::api
{

using namespace xrf::model;

class  XAppRegisterInstanceApi {
public:
    explicit XAppRegisterInstanceApi(const std::shared_ptr<Pistache::Rest::Router>& rtr);
    virtual ~XAppRegisterInstanceApi() = default;
    void init();

    static const std::string base;

private:
    void setupRoutes();

    void registerx_app_instance_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response);
    void x_app_register_instance_api_default_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response);

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
    /// register new xApp instance
    /// </summary>
    /// <remarks>
    /// 
    /// </remarks>
    /// <param name="xAppInstanceId">specific ID for the xApp instance</param>
    /// <param name="xAppProfile"> (optional)</param>
   
   
   // virtual void registerx_app_instance(const std::string &xAppInstanceId, const org::openapitools::server::model::XAppProfile &xAppProfile, Pistache::Http::ResponseWriter &response) = 0;

    //virtual void registerx_app_instance(const std::string &xAppInstanceId, const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter &response) = 0;
    
    virtual void registerx_app_instance(const std::string& xAppInstanceId, const xrf::model::XAppProfile& xAppProfile, Pistache::Http::ResponseWriter &response) = 0;
    
    //virtual void registerx_app_instance(const Pistache::Rest::Request &request, const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter &response) = 0;

};

} // namespace xrf::api

#endif /* XAppRegisterInstanceApi_H_ */

