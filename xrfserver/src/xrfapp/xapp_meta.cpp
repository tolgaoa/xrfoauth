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

void xapp_meta::register_profile(std::vector<std::string>& data, std::string& key){

};

void xapp_meta::update_profile(std::string& key_id){

};

void xapp_meta::delete_profile(std::string& key_id){

};
