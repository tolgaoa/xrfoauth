#ifndef FILE_NRF_API_SERVER_SEEN
#define FILE_NRF_API_SERVER_SEEN

#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"
#ifdef __linux__
#include <vector>
#include <signal.h>
#include <unistd.h>
#endif

//#include "CompleteStoredSearchDocumentApiImpl.h"
//#include "NFInstancesStoreApiImpl.h"
//#include "StoredSearchDocumentApiImpl.h"
//#include "NFInstanceIDDocumentApiImpl.h"
//#include "SubscriptionIDDocumentApiImpl.h"
//#include "SubscriptionsCollectionApiImpl.h"
//#include "DiscNFInstancesStoreApiImpl.h"
#include "AccessTokenRequestApiImpl.h"
#include "xrf_main.hpp"

using namespace xrf::api;
using namespace xrf::app;
class XRFApiServer {
 public:
  XRFApiServer(Pistache::Address addr, xrf_main* xrf_main_inst)
      : m_httpEndpoint(std::make_shared<Pistache::Http::Endpoint>(addr)) {
    m_router  = std::make_shared<Pistache::Rest::Router>();
    m_address = addr.host() + ":" + (addr.port()).toString();

    /*m_completeStoredSearchDocumentApiImpl =
        std::make_shared<CompleteStoredSearchDocumentApiImpl>(
            m_router, nrf_app_inst, m_address);
    m_nfInstancesStoreApiImpl = std::make_shared<NFInstancesStoreApiImpl>(
        m_router, nrf_app_inst, m_address);
    m_storedSearchDocumentApiImpl =
        std::make_shared<StoredSearchDocumentApiImpl>(
            m_router, nrf_app_inst, m_address);
    m_nfInstanceIDDocumentApiImpl =
        std::make_shared<NFInstanceIDDocumentApiImpl>(
            m_router, nrf_app_inst, m_address);
    m_subscriptionIDDocumentApiImpl =
        std::make_shared<SubscriptionIDDocumentApiImpl>(
            m_router, nrf_app_inst, m_address);
    m_subscriptionsCollectionApiImpl =
        std::make_shared<SubscriptionsCollectionApiImpl>(
            m_router, nrf_app_inst, m_address);
    m_discNFInstancesStoreApiImpl =
        std::make_shared<DiscNFInstancesStoreApiImpl>(
            m_router, nrf_app_inst, m_address);*/
    m_accessTokenRequestApiImpl = std::make_shared<AccessTokenRequestApiImpl>(
        m_router, xrf_main_inst, m_address);
  }
  void init(size_t thr = 1);
  void start();
  void shutdown();

 private:
  std::shared_ptr<Pistache::Http::Endpoint> m_httpEndpoint;
  std::shared_ptr<Pistache::Rest::Router> m_router;
  /*std::shared_ptr<CompleteStoredSearchDocumentApiImpl>
      m_completeStoredSearchDocumentApiImpl;
  std::shared_ptr<NFInstancesStoreApiImpl> m_nfInstancesStoreApiImpl;
  std::shared_ptr<StoredSearchDocumentApiImpl> m_storedSearchDocumentApiImpl;
  std::shared_ptr<NFInstanceIDDocumentApiImpl> m_nfInstanceIDDocumentApiImpl;
  std::shared_ptr<SubscriptionIDDocumentApiImpl>
      m_subscriptionIDDocumentApiImpl;
  std::shared_ptr<SubscriptionsCollectionApiImpl>
      m_subscriptionsCollectionApiImpl;
  std::shared_ptr<DiscNFInstancesStoreApiImpl> m_discNFInstancesStoreApiImpl;*/
  std::shared_ptr<AccessTokenRequestApiImpl> m_accessTokenRequestApiImpl;
  std::string m_address;
};

#endif
