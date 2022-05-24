/**
* NRF NFManagement Service
* NRF NFManagement Service. © 2021, 3GPP Organizational Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved. 
*
* The version of the OpenAPI document: 1.2.0-alpha.5
* 
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/

#include "SubscriptionsCollectionApiImpl.h"

namespace org {
namespace openapitools {
namespace server {
namespace api {

using namespace org::openapitools::server::model;

SubscriptionsCollectionApiImpl::SubscriptionsCollectionApiImpl(const std::shared_ptr<Pistache::Rest::Router>& rtr)
    : SubscriptionsCollectionApi(rtr)
{
}

void SubscriptionsCollectionApiImpl::create_subscription(const SubscriptionData &subscriptionData, const Pistache::Optional<Pistache::Http::Header::Raw> &contentEncoding, const Pistache::Optional<Pistache::Http::Header::Raw> &acceptEncoding, Pistache::Http::ResponseWriter &response) {
    response.send(Pistache::Http::Code::Ok, "Do some magic\n");
}

}
}
}
}
