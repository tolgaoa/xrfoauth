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


#ifndef FILE_XAPP_MSG_HPP_SEEN
#define FILE_XAPP_MSG_HPP_SEEN

#include <iostream>
#include <fstream>
#include <openssl/pem.h> 
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <cstdio>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bio.h>

#include <vector>
#include <string>

#include "spdlog/spdlog.h"

#define RND_LENGTH 128
#define SHA256_LENGTH 32
#define MSG_BUFLEN 640
#define PLAIN_LEN 320
#define RSA_SIG_LEN 512
#define	RSA_ENC_LEN 512
#define FINAL_CIPHER_LEN 1024
#define ENCODE_DATA_LEN 1369

#define DEBUG 0
#define WRITE_FILE 0

namespace xrf {
namespace app {


class xapp_msg{
	public:
		explicit xapp_msg();
		xapp_msg(xapp_msg const&) = delete;
		virtual ~xapp_msg();
		void operator=(xapp_msg const&) = delete;

		void print_debug(const std::string&, unsigned char buf[], unsigned int len);
		/*
		 * @param[string] : string
		 * @param[debug_msg] : pointer to debug msg array
		 * @param[debug_msg_len] : debug msg length
		 */

		void write_debug(const std::string&, unsigned char msg[], unsigned int msg_len);
		/*
		 * @param[stirng] : string
		 * @param[write_msg] : address of the msg to be written to file
		 * @param[write_msg_len] : length of the msg to be written to file
		 */

//TA:-----------------------ADDED This------------------------------------------
		void calc_hash(unsigned char m_buf[], unsigned char hm_buf[]);
		/*
		 * @param[m_buf] : message buffer
		 * @param[hm_buf] : hashed message buffer
		 * return void
		 */
//------------------------------------------------------------------------------

		void gen_rand(unsigned char rand_buf[]);
		/*
		 * @param[rand_buf[]] : buffer for random number
		 * updates the random buffer with random number
		 */

		unsigned char* gen_sig(unsigned char hm_buf[]);
		/*
		 * @param[hm_buf] : hash of random number
		 * return signature buffer pointer
		 */

		void prep_msg(unsigned char m_buf[], unsigned char sig_buf[], unsigned char msg_plain_1[], unsigned char msg_plain_2[]);
		/*
		 * @param[m_buf[]] : random number
		 * @param[sig_buf[]] : signature
		 * @param[input1] : address of the first input to be concatenated i.e., m_buf  
		 * @param[input2] : address of the first input to be concatenated i.e., sig_buf
		 * prepares two input buffers with messages for encryption
		 */

		unsigned char* rsa_encrypt(unsigned char* msg_plain, long int msg_plain_len);
		/*
		 * @param[msg_plain]
		 * @param[msg_plain_len]
		 * return pointer to encrypted buffer
		 */
		
		void create_final_msg(std::string&str);
		/*
		 * Create final msg for sending out
		 * return void
		 */
	
};


}
}

#endif
