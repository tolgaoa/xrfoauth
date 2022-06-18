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

	xapp_profile_t xapp_t;
	xapp_i_p["test"] = xapp_t;
	xapp_f_p["test"] = xapp_t;
	test = "test";

};

xapp_meta::~xapp_meta(){};

void xapp_meta::register_profile(std::vector<std::string>& data, std::string& key, std::string& map){
	
	xapp_profile_t xapp_p;
	xapp_p.xapp_instance_func = data[0];
	xapp_p.xapp_instance_id = data[1];
	xapp_p.ipv4_addresses = data[2];
	xapp_p.xapp_instance_status = data[3];
		
	spdlog::debug("Creating xApp Profile");
	//if (map == "imap") xapp_i_p.insert({ key, xapp_p });
	//if (map == "fmap") xapp_f_p.insert({ key, xapp_p });
	spdlog::debug("New xApp Profile Created");

	for (auto i : xapp_i_p){
		std::cout << i.first << std::endl;
		//std::cout << i.second << std::endl;
	}

};

void xapp_meta::update_profile(std::string& key_id){

};

void xapp_meta::delete_profile(std::string& key_id){

};

std::string xapp_meta::testret(){
	std::cout << "returning test" << std::endl;
	return test;
};

void xapp_meta::testset(std::string x){
	test = x;
	std::cout << "setting test" << std::endl;
};


