/*
 * Authentication challenge message creation
 *
 * Controller (RIC) of the Linux Foundation (LF) for distributing access tokens to xApps from an 
 * OAUTH 2.0 server using JSON web tokens as the execution method of the tokens
 *
 *
 * ! file xapp_msg.hpp
 *  \brief
 * \author: Sudip Maitra
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: smaitra@vt.edu
*/

#include "xapp_msg.hpp"

using namespace xrf::app;

extern xapp_msg* xapp_msg_inst;

unsigned char* xapp_msg::generate_rand(){
	spdlog::info("Genering m... \n");
        unsigned char m_buf[RND_LENGTH];
        int m_rc = RAND_bytes(m_buf, sizeof(m_buf));
        if(m_rc != 1) spdlog::info("\nRandom number generation failed\n");

	spdlog::info("\nm:\n");
        for(int i = 0; i < RND_LENGTH; i++){
                printf("%02x",m_buf[i]);
        }
	spdlog::info("\n");
	return m_buf;
}

