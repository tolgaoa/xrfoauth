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


#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

#include "xapp_profile.hpp"

using namespace xrf::app;

extern xapp_profile* xapp_profile_inst;

void xapp_profile::set_instance_id(std::string& instance_id_v){
	spdlog::debug("Setting Instance ID");
	instance_id = instance_id_v;
	spdlog::debug("Set Instance ID");
};

void xapp_profile::create_instance_id(){
	spdlog::debug("Creating Instance ID");
	boost::uuids::uuid uuid = boost::uuids::random_generator()();
	instance_id = to_string(uuid);
	spdlog::debug("Created Instance ID: %s", instance_id.c_str());
};

std::string xapp_profile::get_instance_id() {
	spdlog::debug("Returned Instance ID");
	return instance_id;
};

void xapp_profile::set_instance_name(std::string& instance_name_v){
	spdlog::debug("Setting Instance Name");
	instance_name = instance_name_v;
	spdlog::debug("Set Instance Name");
};

std::string xapp_profile::get_instance_name() {
	spdlog::debug("Return Instance Name");
	return instance_name;
};

void xapp_profile::set_status(std::string& instance_status_v){
	spdlog::debug("Setting Instance Status");
	status = instance_status_v;
	spdlog::debug("Set Instance Status");
};

std::string xapp_profile::get_status() {
	spdlog::debug("Return Instance Status");
	return status;
};

void xapp_profile::set_func(std::string& func_v) {
	spdlog::debug("Seting Instance Function");
	func = func_v;
	spdlog::debug("Set Instance Function");
};

std::string xapp_profile::get_func() {
	spdlog::debug("Return Instance Function");
	return func;
};

void xapp_profile::set_ipv4(std::vector<std::string>& addresses){
	spdlog::debug("Setting Instance Addresses");
	ipv4_addresses = addresses;
	spdlog::debug("Set Instance Addresses");
};

void xapp_profile::create_profile(std::string& instance_id_v, std::string& instance_name_v,
                                  std::string& instance_status_v, std::string& func_v,
                                  std::vector<std::string>& addresses) {
        xapp_profile_inst->set_instance_id(instance_id_v);
        //xapp_profile_inst->create_instance_id();
        xapp_profile_inst->set_instance_name(instance_name_v);
        xapp_profile_inst->set_status(instance_status_v);
        xapp_profile_inst->set_func(func_v);
        xapp_profile_inst->set_ipv4(addresses);
};

void xapp_profile::display() {
	spdlog::info("xApp Instance Info");
	spdlog::info("\tInstance ID: %s", instance_id.c_str());
	spdlog::info("\tInstance Name: %s", instance_id.c_str());
	spdlog::info("\tInstance Function: %s", instance_id.c_str());
	spdlog::info("\tInstance Status: %s", instance_id.c_str());
	if (ipv4_addresses.size() > 0) spdlog::info("\tIPv4 Addr:");
	for (auto address : ipv4_addresses) spdlog::info("\t\t %s", address);

};


