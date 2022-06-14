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

using namespace xrf::app;
using json = nlohmann::json;

extern xrf_client* xrf_client_inst;

static std::size_t callback(const char* in, std::size_t size, std::size_t num, std::string* out){
	const std::size_t totalBytes(size *num);
	out->append(in, totalBytes);
	return totalBytes;
}

xrf_client::xrf_client() {
	headers    = {};
	headers    = NULL;
	//headers    = curl_slist_append(headers, "Accept: application/json");
	headers    = curl_slist_append(headers, "Content-Type: application/json");
	//headers    = curl_slist_append(headers, "charsets: utf-8");
}

/*xrf_client::~xrf_client() {
	spdlog::info("Removing XRF client from xApp");

	for (auto h : handles) {
		curl_multi_remove_handle(curl_multi, h);
		curl_easy_cleanup(h);
	}

	handles.clear();
	curl_multi_cleanup(curl_multi);
	curl_global_cleanup();
	curl_slist_free_all(headers);
}*/

void xrf_client::to_json(nlohmann::json& j, const std::string& kv1, const std::string& kv2){
	j = nlohmann::json();
	j[kv1] = kv2;
}
		
void xrf_client::curl_create_handle(const std::string& uri, const std::string& data,
                         std::string& response_data, uint8_t http_version) {

        CURL *curl;
        CURLcode res;
        std::string readBuffer;

        struct curl_slist *slist1;
        slist1 = NULL;
        slist1 = curl_slist_append(slist1, "Content-Type: application/json");                   
        
        curl = curl_easy_init();

	std::string datakvsta = "{\"Challenge\":\"";
	std::string datakvend =  "\"}";
	std::string datasend = datakvsta + data + datakvend; 
	
	spdlog::debug("JSON created is");
        spdlog::debug(datasend);

	if(curl) {
                curl_easy_setopt(curl, CURLOPT_URL, uri.c_str());
                curl_easy_setopt(curl, CURLOPT_POST, 1);
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist1);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, datasend.c_str());
                //curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
                curl_easy_setopt(curl, CURLOPT_READDATA, &readBuffer);
                res = curl_easy_perform(curl);
                curl_easy_cleanup(curl);

                std::cout << readBuffer << std::endl;
        }	
}

/*void xrf_client::send_curl_easy(const std::string& uri, const std::string& data, 
                    std::string& response_data, uint8_t http_version) {
	
	CURL *curl = curl_create_handle(uri, data, response_data, http_version);
	res = curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	
}*/










