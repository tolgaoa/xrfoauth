/*
 * Client side of the xApp authorization framework to be integrated into the reference RAN Intelligent 
 * Controller (RIC) of the Linux Foundation (LF) for distributing access tokens to xApps from an 
 * OAUTH 2.0 server using JSON web tokens as the execution method of the tokens
 *
 *
 * ! file xapp_profile.cpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#include <iostream>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

#include "xapp_profile.hpp"

using namespace std;
using namespace xrf::app;

extern xapp_profile* xapp_profile_inst;

void xapp_profile::set_instance_id(std::string instance_id){
	spdlog::debug("Setting Instance ID");
	std::cout << xapp_instance_id << std::endl;
	xapp_instance_id = instance_id;
	spdlog::debug("Set Instance ID");
};

void xapp_profile::create_instance_id(){
	std::cout << &xapp_instance_id << std::endl;

	spdlog::debug("Creating Instance ID");
	boost::uuids::uuid uuid = boost::uuids::random_generator()();
	
	std::string s;
	s = to_string(uuid);
	std::cout << s << std::endl;

	xapp_instance_id = to_string(uuid);
	spdlog::debug("Created Instance ID");
};

std::string xapp_profile::get_instance_id() {
	spdlog::debug("Returned Instance ID");
	return xapp_instance_id;
};

void xapp_profile::set_instance_name(std::string instance_name_v){
	spdlog::debug("Setting Instance Name");
	xapp_instance_name = instance_name_v;
	spdlog::debug("Set Instance Name");
};

std::string xapp_profile::get_instance_name() {
	spdlog::debug("Return Instance Name");
	return xapp_instance_name;
};

void xapp_profile::set_status(std::string instance_status_v){
	spdlog::debug("Setting Instance Status");
	xapp_instance_status = instance_status_v;
	spdlog::debug("Set Instance Status");
};

std::string xapp_profile::get_status() {
	spdlog::debug("Return Instance Status");
	return xapp_instance_status;
};

void xapp_profile::set_func(std::string func_v) {
	spdlog::debug("Seting Instance Function");
	xapp_instance_func = func_v;
	spdlog::debug("Set Instance Function");
};

std::string xapp_profile::get_func() {
	spdlog::debug("Return Instance Function");
	return xapp_instance_func;
};

void xapp_profile::set_ipv4(std::string addresses){
	spdlog::debug("Setting Instance Addresses");
	ipv4_addresses = addresses;
	spdlog::debug("Set Instance Addresses");
};

void xapp_profile::create_profile(std::string instance_id_v, std::string instance_name_v,
                                  std::string instance_status_v, std::string func_v,
                                  std::string addresses) {
        //xapp_profile_inst->set_instance_id(instance_id_v);
        xapp_profile_inst->create_instance_id();
        xapp_profile_inst->set_instance_name(instance_name_v);
        xapp_profile_inst->set_status(instance_status_v);
        xapp_profile_inst->set_func(func_v);
        xapp_profile_inst->set_ipv4(addresses);
};

void xapp_profile::profile_to_json(nlohmann::json& data){
	data["xAppInstanceId"]   = xapp_instance_id;
	data["xAppInstanceName"] = xapp_instance_name;
	data["xAppStatus"]       = xapp_instance_status;
	data["xAppFunc"]	 = xapp_instance_func;
	data["xAppIpv4"] 	 = ipv4_addresses;
	data["xAppLocation"] 	 = xapp_instance_loc;
	data["xAppClients"] 	 = xapp_clients;
}

void xapp_profile::profile_to_vector_s(std::vector<std::string>& data){
	data.push_back(xapp_instance_id);
	data.push_back(xapp_instance_name);
	data.push_back(xapp_instance_status);
	data.push_back(xapp_instance_func);
	data.push_back(ipv4_addresses);
}


void xapp_profile::display() {
	spdlog::info("xApp Instance Info");
	spdlog::info("\tInstance ID: {}", xapp_instance_id.c_str());
	spdlog::info("\tInstance Name: {}", xapp_instance_name.c_str());
	spdlog::info("\tInstance Function: {}", xapp_instance_func.c_str());
	spdlog::info("\tInstance Status: {}", xapp_instance_status.c_str());
	spdlog::info("\tInstance Address: {}", ipv4_addresses.c_str());
	spdlog::info("\tInstance Location: {}", xapp_instance_loc.c_str());
	spdlog::info("\tInstance Clients: {}", xapp_clients);

};


