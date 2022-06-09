#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <thread>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include "xappclient_main.hpp"


static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

void to_json(nlohmann::json& j, const std::string& s){
	j = nlohmann::json();
	j["challenge"] = "testchallenge";	
}

int main(int argc, char** argv){

	std::string data = "Sudip's String A";
	nlohmann::json json_data = {};
	std::string content_type = "application/json";
	to_json(json_data, data);

	std::cout << json_data << std::endl;
	std::cout << json_data.dump().c_str() << std::endl;

	CURL *curl;
	CURLcode res;
	std::string readBuffer;
	//readBuffer.resize(100);

	struct curl_slist *slist1;
  	slist1 = NULL;
	slist1 = curl_slist_append(slist1, "Content-Type: application/json");			
	
	curl = curl_easy_init();
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, "http://10.0.0.135:9090/init/auth");
		curl_easy_setopt(curl, CURLOPT_POST, 1);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist1);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "{\"Challenge\":\"Sudip's String A\"}");
		//curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
		curl_easy_setopt(curl, CURLOPT_READDATA, &readBuffer);
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);

		std::cout << readBuffer << std::endl;
	}

	return 0;
}
