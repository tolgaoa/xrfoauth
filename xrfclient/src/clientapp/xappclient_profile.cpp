/*
 * Client side of the xApp authorization framework to be integrated into the reference RAN Intelligent 
 * Controller (RIC) of the Linux Foundation (LF) for distributing access tokens to xApps from an 
 * OAUTH 2.0 server using JSON web tokens as the execution method of the tokens
 *
 *
 * ! file xappclient_profile.cpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/


#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

#include "xappclient_profile.hpp"

using namespace xappclient;

void xappclient_profile::set_xappclient_instance_id(const std::string& instance_id){
	xappclient_instance_id = instance_id;
};

std::string xappclient_profile::get_xappclient_instance_id() const{
	return xappclient_instance_id;
};

void xappclient_profile::set_xappclient_instance_name(const std::string& instance_name){
	xappclient_instance_name = instance_name;
};

std::string xappclient_profile::get_xappclient_instance_name() const{
	return xappclient_instance_name;
};

void xappclient_profile::set_xappclient_status(const std::string& instance_status){
	xappclient_status = instance_status;
};

std::string xappclient_profile::get_xappclient_status() const {
	return xappclient_status;
};

void xappclient_profile::set_xappclient_ipv4(const std::vector<struct in_addr>& addresses){
	ipv4_addresses = addresses;
};

void xappclient_profile::display() const {
};


