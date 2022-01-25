/**
* NRF OAuth2
* NRF OAuth2 Authorization. © 2021, 3GPP Organizational Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved. 
*
* The version of the OpenAPI document: 1.2.0-alpha.3
* 
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/
/*
 * AccessTokenRequestApi.h
 *
 * 
 */

#ifndef AccessTokenRequestApi_H_
#define AccessTokenRequestApi_H_


#include <pistache/http.h>
#include <pistache/router.h>
#include <pistache/http_headers.h>
#include <pistache/optional.h>

#include <utility>

#include "AccessTokenErr.h"
#include "AccessTokenRsp.h"
#include "NFType.h"
#include "PlmnId.h"
#include "PlmnIdNid.h"
#include "ProblemDetails.h"
#include "RedirectResponse.h"
#include "Snssai.h"
#include <string>

namespace org::openapitools::server::api
{

class  AccessTokenRequestApi {
public:
    explicit AccessTokenRequestApi(const std::shared_ptr<Pistache::Rest::Router>& rtr);
    virtual ~AccessTokenRequestApi() = default;
    void init();

    static const std::string base;

private:
    void setupRoutes();

    void access_token_request_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response);
    void access_token_request_api_default_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response);

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
    /// Access Token Request
    /// </summary>
    /// <remarks>
    /// 
    /// </remarks>
    virtual void access_token_request(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter &response) = 0;

};

} // namespace org::openapitools::server::api

#endif /* AccessTokenRequestApi_H_ */

