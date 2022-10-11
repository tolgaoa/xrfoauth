/*
 * Client side of the xApp authorization framework to be integrated into the reference RAN Intelligent 
 * Controller (RIC) of the Linux Foundation (LF) for distributing access tokens to xApps from an 
 * OAUTH 2.0 server using JSON web tokens as the execution method of the tokens
 *
 *
 * ! file xappclient_main.cpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#include "xapp_main.hpp"
#include <unistd.h>

using namespace xrf::app;

extern xapp_main* xapp_main_inst;
xrf_client* xrf_client_inst = nullptr;
xapp_msg* xapp_msg_inst = nullptr;
xapp_profile* xapp_profile_inst = nullptr;
xapp_jwt* xapp_jwt_inst = nullptr;

std::map<int, xapp_profile_t> disc_map;
std::unordered_map<std::string, std::string> token_key_map; // kid to pubkey map
std::string chosen_xapp_id;
std::unordered_map<std::string, std::string> token_map; // kid to token map

auto wbeginjwks = std::chrono::high_resolution_clock::now();
auto wbeginremote = std::chrono::high_resolution_clock::now();
clock_t cstartjwks = clock();
clock_t cstartremote = clock();

const char *nc = "CLIENT_COUNT";

int pclient_jwks = 0;
int pclient_remote = 0;

template<class T> std::string toString(const T& x)
{
  std::ostringstream ss;
  ss << x;
  return ss.str();
}

std::vector<std::string> splitString(const std::string& str)
{
    std::vector<std::string> tokens;
 
    std::string::size_type pos = 0;
    std::string::size_type prev = 0;
    while ((pos = str.find("\\n", prev)) != std::string::npos) {
        tokens.push_back(str.substr(prev, pos - prev));
        prev = pos + 1;
    }
    tokens.push_back(str.substr(prev));
 
    return tokens;
}

void xapp_main::register_with_xrf(const std::string& xrfaddress) {
	std::string response_from_xrf;
	std::string str = "test";	
	
	nlohmann::json data;
	std::vector<std::string> data_s;
	xapp_profile_inst->profile_to_json(data);
	xapp_profile_inst->profile_to_vector_s(data_s);
	xrf_client_inst->curl_create_handle(xrfaddress, data, response_from_xrf,1);
	
}

void xapp_main::generate_profile(std::string instance_id_v, std::string instance_name_v,
		  std::string instance_status_v, std::string func_v,
		  std::string addresses, std::string loc_v, int cap){
	
	xapp_profile *xapp_p = new xapp_profile(instance_id_v, instance_name_v, instance_status_v, func_v, addresses, loc_v, cap);
	xapp_profile_inst = xapp_p;
};

void xapp_main::display_profile() {
	xapp_profile_inst->display();
};


void xapp_main::sendauth_to_xrf(const std::string& challenge, const std::string& xrfaddress){
	
	std::string response_from_xrf;
	std::string str;

	spdlog::info("Creating challenge");
	xapp_msg_inst->create_final_msg(str);
	spdlog::info("Challenge created");

	xrf_client_inst->curl_create_handle(xrfaddress, str, response_from_xrf, 1);
	spdlog::debug("Authentication challenge response from XRF: {}", response_from_xrf);
	//-----------------Process for XRF ID authentication by xApp----------------------------
	unsigned char xrf_challenge[RND_LENGTH];
	int xrf_auth_result = xapp_msg_inst->final_verification(response_from_xrf, xrf_challenge);
	if (xrf_auth_result == 1) spdlog::info("Initial authentication successful");
	else if (xrf_auth_result == 0) spdlog::warn("Initial authentication failed");
	else spdlog::error("Unspecified signature verification error");
}

void xapp_main::send_discovery_request(std::string& xrfaddressbase, const std::string& targetxApp, const std::string& targetLoc){

	spdlog::info("Sending xApp Disocovery Request to XRF");
	std::string response_from_xrf;
	xrf_client_inst->curl_create_get_handle(xrfaddressbase, disc_map, 1, targetxApp, targetLoc);
	
	int targetLoc_i = std::stoi(targetLoc);
	int distdiff = 100; //initial value

	if (disc_map.size() == 0) spdlog::warn("no valid xApp discovered");
	else{	
		for (auto i : disc_map) {
			if ( abs(i.second.location - targetLoc_i) < distdiff) {
				distdiff = abs(i.second.location - targetLoc_i);
				chosen_xapp_id = i.second.id;
			}
		}
		spdlog::info("Chosen xApp with ID: {}", chosen_xapp_id);
	}
};

void xapp_main::send_token_req(const std::string& xrfaddress){

	std::string local_xapp_id = xapp_profile_inst->get_instance_id();
	spdlog::debug("Local xApp ID is: {}", local_xapp_id);
	std::string target_xapp_id = chosen_xapp_id;
	spdlog::debug("Target xApp ID for token request is: {}", target_xapp_id);
	std::string scope = "write";
	spdlog::debug("Requested access scope is: {}", scope);

	nlohmann::json data;
	data["requester_ID"] = local_xapp_id;
	data["target_ID"] = target_xapp_id;
	data["scope"] = scope;



	std::string response_from_xrf;

	xrf_client_inst->curl_create_token_req_handle(xrfaddress, data, response_from_xrf, 1);
	spdlog::debug("Token ----- {} ----- received for xApp: {}", response_from_xrf, target_xapp_id);

	token_map[target_xapp_id] = response_from_xrf;

};

void xapp_main::validate_token_self(const std::string& xrfaddress, std::string& token, bool& validity) {

        //Get Client count
        const char *tmp = getenv("CLIENT_COUNT");
        std::string tc(tmp ? tmp : "");
        if (tc.empty()) {
                spdlog::error("Client count not found");
                exit(EXIT_FAILURE);
        }
        spdlog::info("Client count is: {}", tc);


	using namespace jwt::params;
	
	std::string kid;
        auto decoded = jwt::decode(token, algorithms({"none"}), verify(false));

        spdlog::debug("======Decoding Token Header and Payload======");
        spdlog::debug("===Header===");
	spdlog::debug("{}", toString(decoded.header()));
        spdlog::debug("===Payload===");
	spdlog::debug("{}", toString(decoded.payload()));

	std::string header_raw = toString(decoded.header());
	std::vector<std::string> header;	
	boost::split(header, header_raw, boost::is_any_of(","), boost::token_compress_on);
        for (auto i : header){
                i.erase(remove(i.begin(), i.end(), '"'), i.end());
                i.erase(remove(i.begin(), i.end(), '{'), i.end());
                i.erase(remove(i.begin(), i.end(), '}'), i.end());

		std::vector<std::string> hkv;
		boost::split(hkv, i, boost::is_any_of(":"), boost::token_compress_on);
		for (auto k : hkv){
			if (hkv[0] == "kid") {
				kid = hkv[1];
			}
		}
        }
	spdlog::debug("Key ID is: {}", kid);

	std::error_code ec;
	
	if (token_key_map.find(kid) == token_key_map.end()) {
		
		xrf_client_inst->curl_create_jwks_req_handle(xrfaddress, token_key_map, 1, kid);
		spdlog::info("Public key for token not found. Contacting XRF Server");
	}

	auto dec_obj = jwt::decode(token, algorithms({"RS256"}), ec, secret(token_key_map.at(kid)), verify(true));

	assert (ec);
	validity = true;
	
	//*************************************This block uses the other jwt library: cpp-jwt*********************************
	/*
	spdlog::debug("======Decoding Token Header and Payload======");
	spdlog::debug("===Header===");
        for(auto& e : decoded.get_header_claims()){
		spdlog::debug("{} = {}", toString(e.first), toString(e.second));
                if (e.first == "kid") {
                        kid = toString(e.second);
                        kid = kid.substr(1, kid.size() - 2);
                }
        }
	spdlog::debug("===Payload===");
        for(auto& e : decoded.get_payload_claims())
		spdlog::debug("{} = {}", toString(e.first), toString(e.second));


        if(kid.empty()) spdlog::error("Did not find key id in JWT header");
        else spdlog::debug("Key id is: {}", kid);

	xrf_client_inst->curl_create_jwks_req_handle(xrfaddress, token_key_map, 1, kid);

	spdlog::debug("The received key is: {}", token_key_map.at(kid));
	
	std::string str =  token_key_map.at(kid);
	std::vector<std::string> tokens = splitString(str);
	std::string finalkey;

	int c = 0;
	for (auto i : tokens) {
		if(c > 0) i.erase(0,1);
		i.erase(remove(i.begin(), i.end(), '}'), i.end());
		finalkey.append(i);
		finalkey.append("\n");
		//std::cout << i << std::endl;        
		c++;
	}

	auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::rs256(tokenkeypub3, "", "", ""))
		.with_issuer("nssl.xrf");

	verifier.verify(decoded);
	*/
	//***************************************************************************************************************
	//
	
	if (pclient_jwks == std::stoi(tc)) {
		auto wendjwks = std::chrono::high_resolution_clock::now(); //Stop client wall clock
		clock_t cendjwks = clock(); // Stop client cpu clock
		//---------------------------------------------------------------------------
		double celapsed = double(cendjwks - cstartjwks)/CLOCKS_PER_SEC; // calculate cpu time
		spdlog::debug("CPU-time: {} ms", celapsed * 1000.0);
		auto welapsed = std::chrono::duration<double, std::milli>(wendjwks - wbeginjwks); //calculate wall time
		spdlog::debug("Wall-time: {} ms", welapsed.count());

		auto celapseds = std::to_string(celapsed*1000.0);
		auto welapseds = std::to_string(welapsed.count());

		std::ofstream out("latencyjwks.txt");
		out << celapseds;
		out << "\n";
		out << welapseds;
		out << "\n";
		out.close();
	}
};

void xapp_main::validate_token_remote(const std::string& xrfaddress, std::string& token, bool& validity) {

        //Get Client count
        const char *tmp = getenv("CLIENT_COUNT");
        std::string tc(tmp ? tmp : "");
        if (tc.empty()) {
                spdlog::error("Client count not found");
                exit(EXIT_FAILURE);
        }
        spdlog::info("Client count is: {}", tc);

	spdlog::info("Performing remote token introspection");
	spdlog::debug("Token is: {}", token);
        nlohmann::json data;
        data["token"] = token;
	std::cout << data << std::endl;

        xrf_client_inst->curl_create_intro_req_handle(xrfaddress, 1, data, validity);

        if (pclient_jwks == std::stoi(tc)) {
                auto wendremote = std::chrono::high_resolution_clock::now(); //Stop client wall clock
                clock_t cendremote = clock(); // Stop client cpu clock
                //---------------------------------------------------------------------------
                double celapsed = double(cendremote - cstartremote)/CLOCKS_PER_SEC; // calculate cpu time
                spdlog::debug("CPU-time: {} ms", celapsed * 1000.0);
                auto welapsed = std::chrono::duration<double, std::milli>(wendremote - wbeginremote); //calculate wall time
                spdlog::debug("Wall-time: {} ms", welapsed.count());

                auto celapseds = std::to_string(celapsed*1000.0);
                auto welapseds = std::to_string(welapsed.count());

                std::ofstream out("latencyremote.txt");
                out << celapseds;
                out << "\n";
                out << welapseds;
                out << "\n";
                out.close();
        }
};

void xapp_main::send_client_connection(const std::string& addr) {

	std::string temptoken = token_map.begin()->second;	
	spdlog::info("Sending client connection");
	xrf_client_inst->curl_create_client_req(addr, 1, temptoken);

};
