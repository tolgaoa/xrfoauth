/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 *
 * XRF client for sending out CURL commands
 *
 * ! file xrf_client.cpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#include "xrf_client.hpp"

using namespace Pistache::Http;
using namespace Pistache::Htpp:Mime;
using namespace xrf::app;
using json = nhlohmann::json;

extern xrf_client* xrf_client_inst;

static std::size_t callback(const char* in, std::size_t size, std::size_t num, std::string* out){
	const std::size_t totalBytes(size *num);
	out->append(in, totalBytes);
	return totalBytes;
}

xrf_client::xrf_client() {
	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl_multi = curl_multi_init();
	handles    = {};
	headers    = NULL;
	headers    = curl_slist_append(headers, "Accept: application/json");
	headers    = curl_slist_append(headers, "Content-Type: application/json");
	headers    = curl_slist_append(headers, "charsets: utf-8");
}

xrf_client::~xrf_client() {
	spdlog::info("Removing XRF client from xApp");

	for (auto h : handles) {
		curl_multi_remove_handle(curl_multi, h);
		curl_easy_cleanup(h);
	}

	handles.clear();
	curl_multi_cleanup(curl_multi);
	curl_global_cleanup();
	curl_slist_free_all(headers);
}


		
CURL* curl_create_handle(const std::string& uri, const std::string& data,
                         std::string& response_data, uint8_t http_version) {
	CURL* curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_URL, uri.c_str());
		curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, NF_CURL_TIMEOUT_MS);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
   		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data.length());
    		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
	}
}

void xrf_client::send_curl_multi(const std::string& uri, const std::string& data,
                                 std::string& response_data, uint8_t http_version) {

	CURL* tmp = curl_create_handle(uri, data, response_data, http_version);
	curl_multi_add_handle(curl_multi, tmp);
	handles.push_back(tmp);
}

void xrf_client::perform_curl_multi() {

	int still_running = 0, numfds = 0;
	CURLMcode code = curl_multi_perform(curl_multi, &still_running);

	do {
		code = curl_multi_wait(curl_multi, NULL, 0, 200000, &numfds);
		if (code != CURLM_OK) spdlog::warn("curl_multi_wait() returned %d!", code);
		curl_multi_perform(curl_multi, &still_running);
	
	} while (still_running);
	curl_release_handles();
}

void xrf_client::wait_curl_end() {
  // block until activity is detected on at least one of the handles or
  // MAX_WAIT_MSECS has passed.
  int still_running = 0, numfds = 0;
  do {
    CURLMcode code = curl_multi_perform(curl_multi, &still_running);
    if (code == CURLM_OK) {
      code = curl_multi_wait(curl_multi, NULL, 0, MAX_WAIT_MSECS, &numfds);
      if (code != CURLM_OK) break;
    } else {
      break;
    }
  } while (still_running);

  curl_release_handles();

}









