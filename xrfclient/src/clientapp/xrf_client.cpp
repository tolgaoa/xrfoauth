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

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

void erase_every_even(std::vector<std::string>& v) {
	if ((v.size() % 2) == 0)
		v.pop_back();

	auto size = (v.size() / 2) + 1;

	for (size_t i = 1; i < size; ++i)
		v.erase(v.begin() + i);
}

void erase_every_odd(std::vector<std::string>& v) {
	if ((v.size() % 2) > 0)
		v.pop_back();

	auto size = v.size() / 2;

	for (size_t i = 0; i < size; ++i)
		v.erase(v.begin() + i);
}

void erase_preamble(std::string s){
	s.erase(0,3);
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
	
	//spdlog::debug("JSON created is");
        //spdlog::debug(datasend);

	if(curl) {
                curl_easy_setopt(curl, CURLOPT_URL, uri.c_str());
                curl_easy_setopt(curl, CURLOPT_POST, 1);
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist1);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, datasend.c_str());
                //curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
                //curl_easy_setopt(curl, CURLOPT_READDATA, &readBuffer);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
                res = curl_easy_perform(curl);
                curl_easy_cleanup(curl);
        }
	
        std::map<std::string, std::string> request;
        std::vector<std::string> kvpairs;
        boost::split(kvpairs, readBuffer, boost::is_any_of("&"), boost::token_compress_on);
	
        std::vector<std::string> kv;
        for (auto i : kvpairs){
                boost::split(kv, i, boost::is_any_of(":"), boost::token_compress_on);
                if (kv.size() != 2){
                        spdlog::warn("Invalid Authentication Request--Expecting single KVpair--Received more");
                }else request[kv[0]] = kv[1];
                //spdlog::info("(Key, Value):  %s, %s \n", kv[0].c_str(), kv[1].c_str());
        }
        std::string rec_str = kv[1];
        rec_str.erase(rec_str.begin()+0);
        rec_str.erase(rec_str.end()-1);
        rec_str.erase(rec_str.end()-1);
	
	response_data = rec_str;
}

void xrf_client::curl_create_handle(const std::string& uri, const nlohmann::json& data,
		std::string& response_data, uint8_t http_version){

	CURL *curl;
        CURLcode res;
        std::string readBuffer;

        struct curl_slist *slist1;
        slist1 = NULL;
        slist1 = curl_slist_append(slist1, "Content-Type: application/json");
	//slist1 = curl_slist_append(headers, "Accept: application/json");
	//slist1 = curl_slist_append(headers, "charsets: utf-8");


        curl = curl_easy_init();

	const auto s = data.dump(); 
	std::string s1="";
	for(int i=0;i<s.length();i++)
	{
	    if(s[i]!=',')
	    s1=s1+s[i];
	    else
	    s1=s1+s[i]+" ";
	}

        if(curl) {
                curl_easy_setopt(curl, CURLOPT_URL, uri.c_str());
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist1);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, s1.c_str());
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
                res = curl_easy_perform(curl);
                curl_easy_cleanup(curl);
        }
}

void xrf_client::curl_create_handle(const std::string& uri, const std::vector<std::string>& data,
                         std::string& response_data, uint8_t http_version) {

        CURL *curl;
        CURLcode res;
        std::string readBuffer;

        struct curl_slist *slist1;
        slist1 = NULL;
        slist1 = curl_slist_append(slist1, "Content-Type: application/json");


        if(curl) {
                curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 102400L);
                curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
                curl_easy_setopt(curl, CURLOPT_URL, uri.c_str());
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist1);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)128);
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
                res = curl_easy_perform(curl);
                curl_easy_cleanup(curl);
        }


}

void xrf_client::curl_create_get_handle(const std::string& uri,
					std::map<int, xapp_profile_t>& disc_map, uint8_t http_version,
					const std::string& targetxApp, const std::string targetLoc){
	
        CURL *curl;
        CURLcode res;
        std::string readBuffer;
	
	std::string fulluri = uri;;
	fulluri.push_back('?');
	fulluri.append("targetxApp");
	fulluri.push_back('=');
	fulluri.append(targetxApp);
	fulluri.push_back('&');
	fulluri.append("targetLoc");
	fulluri.push_back('=');
	fulluri.append(targetLoc);

	spdlog::debug("Target Query is: {}", fulluri);

        if(curl) {
		curl = curl_easy_init();
                curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 102400L);
                curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
		curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
                curl_easy_setopt(curl, CURLOPT_URL, fulluri.c_str());
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
		curl_easy_setopt(curl, CURLOPT_FTP_SKIP_PASV_IP, 1L);
		curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
                res = curl_easy_perform(curl);
                curl_easy_cleanup(curl);
        }

	spdlog::debug("Incoming xApp Profiles: {}", readBuffer);


        std::vector<std::string> raw_disc;
        boost::split(raw_disc, readBuffer, boost::is_any_of("&"), boost::token_compress_on);
	
	/*for (int i=0; i < raw_disc.size(); i++) {
                std::cout << raw_disc[i] << std::endl;
        }*/

	/*std::cout << "" << std::endl;
	std::cout << "" << std::endl;*/

	erase_every_odd(raw_disc);

        /*for (int i=0; i < raw_disc.size(); i++) {
                std::cout << raw_disc[i] << std::endl;
        }*/

	/*std::cout << "" << std::endl;
	std::cout << "" << std::endl;*/

	int c = 0;
        for (auto i : raw_disc){
		c++;
		i.erase(0,3);
		i.erase(remove(i.begin(), i.end(), '"'), i.end());
		i.erase(remove(i.begin(), i.end(), '{'), i.end());
		i.erase(remove(i.begin(), i.end(), '}'), i.end());

        	std::vector<std::string> proc_disc;
		boost::split(proc_disc, i, boost::is_any_of(","), boost::token_compress_on);
			xapp_profile_t xapp_p;
		for (auto j : proc_disc){
			std::vector<std::string> kv;
			//xapp_profile_t xapp_p;
			boost::split(kv, j, boost::is_any_of(":"), boost::token_compress_on);
			for (auto k : kv){
				if (kv[0] == "id") {
					xapp_p.id = kv[1];
					//std::cout << kv[1] << std::endl;
				}
				if (kv[0] == "ipv4") {
					xapp_p.ipv4 = kv[1];
					//std::cout << kv[1] << std::endl; 
				}
				if (kv[0] == "location") {
					xapp_p.location = std::stoi(kv[1]);
					//std::cout << kv[1] << std::endl; 
				}
			}
		}
		disc_map[c] = xapp_p;
		//std::cout << xapp_p.to_string() << std::endl;
        }
};

void xrf_client::curl_create_token_req_handle(const std::string& uri, nlohmann::json& data, 
		std::string& response_data, uint8_t http_version){
	
        CURL *curl;
        CURLcode res;
        std::string readBuffer;

        struct curl_slist *slist1;
        slist1 = NULL;
        slist1 = curl_slist_append(slist1, "Content-Type: application/json");

        curl = curl_easy_init();

	std::string s = data.dump();
	spdlog::debug("Token request: {}" , s);

        if(curl) {
                curl_easy_setopt(curl, CURLOPT_URL, uri.c_str());
                curl_easy_setopt(curl, CURLOPT_POST, 1);
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist1);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, s.c_str());
                //curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
                //curl_easy_setopt(curl, CURLOPT_READDATA, &readBuffer);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
                res = curl_easy_perform(curl);
                curl_easy_cleanup(curl);
        }

	std::map<std::string, std::string> request;
        std::vector<std::string> kvpairs;
        boost::split(kvpairs, readBuffer, boost::is_any_of(","), boost::token_compress_on);
       
       	/*for (int i=0; i < kvpairs.size(); i++) {
                std::cout << kvpairs[i] << std::endl;
        }*/

        std::vector<std::string> kv;
        
	for (auto i : kvpairs){
                i.erase(remove(i.begin(), i.end(), '"'), i.end());
                i.erase(remove(i.begin(), i.end(), '{'), i.end());
                i.erase(remove(i.begin(), i.end(), '}'), i.end());
       
       		boost::split(kv, i, boost::is_any_of(":"), boost::token_compress_on);
                request[kv[0]] = kv[1];
        }
        response_data = request.at("access_token");
        //response_data = readBuffer;
	
	

};


void xrf_client::curl_create_jwks_req_handle(const std::string& uri,
                                        std::unordered_map<std::string, std::string>& token_key_map, uint8_t http_version,
                                        std::string& kid){

        CURL *curl;
        CURLcode res;
        std::string readBuffer;

        std::string fulluri = uri;;
        fulluri.push_back('?');
        fulluri.append("keyid");
        fulluri.push_back('=');
        fulluri.append(kid);

        spdlog::debug("Target Query is: {}", fulluri);

        if(curl) {
                curl = curl_easy_init();
                curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 102400L);
                curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
                curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
                curl_easy_setopt(curl, CURLOPT_URL, fulluri.c_str());
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
                curl_easy_setopt(curl, CURLOPT_FTP_SKIP_PASV_IP, 1L);
                curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
                res = curl_easy_perform(curl);
                curl_easy_cleanup(curl);
        }

        //if (readBuffer.empty() == 0) spdlog::error("No key received from server that corresponds to the given key id");
	//spdlog::debug("Incoming public Key is: {}", readBuffer);

        std::map<std::string, std::string> request;
        std::vector<std::string> kvpairs;
        boost::split(kvpairs, readBuffer, boost::is_any_of("&"), boost::token_compress_on);

        std::vector<std::string> kv;
        for (auto i : kvpairs){
                boost::split(kv, i, boost::is_any_of(":"), boost::token_compress_on);
                if (kv.size() != 2){
                        spdlog::warn("Invalid Response--Expecting single KVpair--Received more");
                }else request[kv[0]] = kv[1];
                //spdlog::info("(Key, Value):  %s, %s \n", kv[0].c_str(), kv[1].c_str());
        }

	std::string r = kv[1];
	r.erase(remove(r.begin(), r.end(), '"'), r.end());
	token_key_map[kid] = r;
	spdlog::debug("Received key: {}", r);

};

void xrf_client::curl_create_intro_req_handle(const std::string& uri,
                                  uint8_t http_version, nlohmann::json& json_data, bool& validity) {

        CURL *curl;
        CURLcode res;
        std::string readBuffer;

        struct curl_slist *slist1;
        slist1 = NULL;
        slist1 = curl_slist_append(slist1, "Content-Type: application/json");

        curl = curl_easy_init();

	std::string s = json_data.dump();
        
	if(curl) {
                curl_easy_setopt(curl, CURLOPT_URL, uri.c_str());
                curl_easy_setopt(curl, CURLOPT_POST, 1);
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist1);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, s.c_str());
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
                res = curl_easy_perform(curl);
                curl_easy_cleanup(curl);
        }

        std::vector<std::string> kvpairs;
        boost::split(kvpairs, readBuffer, boost::is_any_of(","), boost::token_compress_on);
        std::vector<std::string> kv;
        std::string resp;

        for (auto i : kvpairs){
                i.erase(remove(i.begin(), i.end(), '"'), i.end());
                i.erase(remove(i.begin(), i.end(), '{'), i.end());
                i.erase(remove(i.begin(), i.end(), '}'), i.end());

                boost::split(kv, i, boost::is_any_of(":"), boost::token_compress_on);
                resp = kv[1];
                //spdlog::debug("(Key, Value):  {}, {}", kv[0], kv[1]);
        }

	if (resp == "true") validity = true;
	else validity = false;


};

void xrf_client::curl_create_client_req(const std::string& uri,
                                        uint8_t http_version, std::string& token) {

	CURLcode ret;
	CURL *hnd;
	struct curl_slist *slist1;

	std::string readBuffer;

	slist1 = NULL;
	slist1 = curl_slist_append(slist1, "Accept: application/json");

        std::string datakvsta = "Authorization: Bearer ";
        std::string datasend = datakvsta + token;

	slist1 = curl_slist_append(slist1, datasend.c_str());
	
	hnd = curl_easy_init();
	curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, 102400L);
	curl_easy_setopt(hnd, CURLOPT_URL, uri.c_str());
	curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, "{\"Key\":\"Value\"}");
	curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)15);
	curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist1);
	curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.68.0");
	curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
	curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);
	curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
	curl_easy_setopt(hnd, CURLOPT_FTP_SKIP_PASV_IP, 1L);
	curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
	
	ret = curl_easy_perform(hnd);
	curl_easy_cleanup(hnd);
};




