/*
 * Client side of the xApp authorization framework to be integrated into the reference RAN Intelligent 
 * Controller (RIC) of the Linux Foundation (LF) for distributing access tokens to xApps from an 
 * OAUTH 2.0 server using JSON web tokens as the execution method of the tokens
 *
 * Store xApp metadata
 *
 * ! file xapp_meta.cpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#include "xapp_meta.hpp"

using namespace xrf::app;

extern xapp_meta* xapp_meta_inst;

xapp_meta::xapp_meta(){

	xapp_profile_t *xapp_t;
       
	xapp_t->xapp_instance_id = " "; 
	xapp_t->xapp_instance_status = " ";
	xapp_t->ipv4_addresses = " ";
	xapp_t->xapp_instance_func = " ";
	xapp_t->xapp_instance_loc = " ";
	xapp_t->xapp_instance_name = " ";
	xapp_t->xapp_clients = 0;
};

xapp_meta::~xapp_meta(){};

void xapp_meta::register_profile(std::vector<std::string>& data, std::string& key, std::string& map, std::unordered_map<std::string, xapp_profile_t>& xapp_map){
	
	xapp_profile_t xapp_p;
	xapp_p.xapp_clients = std::stoi(data[0]);
	xapp_p.xapp_instance_func = data[1];
	xapp_p.xapp_instance_id = data[2];
	xapp_p.xapp_instance_name = data[3];
	xapp_p.ipv4_addresses = data[4];
	xapp_p.xapp_instance_loc = data[5];
	xapp_p.xapp_instance_status = data[6];
		
	spdlog::debug("Loading xApp Profile");
	//if (map == "imap") xapp_map[key] = xapp_p;
	if (map == "imap") xapp_map.insert({ key, xapp_p });
	//if (map == "fmap") xapp_map[key] = xapp_p;
	if (map == "fmap") xapp_map.insert({ key, xapp_p });
	spdlog::debug("New xApp Profile Loaded");

	/*
        for (auto i : xapp_map){
                std::cout << i.first << std::endl;
                std::cout << i.second.to_string() << std::endl;
        }*/


};

void xapp_meta::update_profile(std::string& key_id, std::unordered_map<std::string, xapp_profile_t>& xapp_map_i, std::unordered_map<std::string, xapp_profile_t>& xapp_map_f, xapp_profile_t xapp_profile){

	spdlog::info("Updating xApp Profile: {}", key_id);
	xapp_map_i.at(key_id) = xapp_profile;

        std::unordered_map<std::string, xapp_profile_t>::iterator itf = xapp_map_f.begin();
        while(itf != xapp_map_f.end()) {
                if(itf->second.xapp_instance_id == key_id)
                    break;
                itf++;
        }
	if (itf != xapp_map_f.end()) xapp_map_f.erase(itf);
	xapp_map_f[xapp_profile.xapp_instance_func] = xapp_profile;

};

void xapp_meta::delete_profile(std::string& key_id, std::unordered_map<std::string, xapp_profile_t>& xapp_map_i, std::unordered_map<std::string, xapp_profile_t>& xapp_map_f){

	spdlog::info("Removing xApp with ID: {}", key_id);
	std::unordered_map<std::string, xapp_profile_t>::iterator it = xapp_map_i.find(key_id);
	if (it != xapp_map_i.end()) xapp_map_i.erase(it);
	
	std::unordered_map<std::string, xapp_profile_t>::iterator itf = xapp_map_f.begin();
	while(itf != xapp_map_f.end()) {
		if(itf->second.xapp_instance_id == key_id)
		    break;
		itf++;
	}
	if (itf != xapp_map_f.end()) xapp_map_f.erase(itf);

};

void xapp_meta::display_map(std::unordered_map<std::string, xapp_profile_t>& xapp_map) {

	spdlog::info("==================Displaying Current xApp Map======================");
	for (std::pair<std::string, xapp_profile_t> element : xapp_map)
		spdlog::debug("Map Key: {} , Map Entry: {}", element.first, element.second.to_string());

};


