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
#include <algorithm>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <cstdio>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "spdlog/spdlog.h"

#define RND_LENGTH 128
#define SHA256_LENGTH 32
#define MSG_BUFLEN 640
#define PLAIN_LEN 320
#define RSA_SIG_LEN 512
#define RSA_ENC_LEN 512

namespace xrf {
namespace app {


class xapp_msg{
	public:
		explicit xapp_msg();
		xapp_msg(xapp_msg const&) = delete;
		virtual ~xapp_msg();
		void operator=(xapp_msg const&) = delete;

		unsigned char* generate_rand();
		/*
		 * return pointer to unsigned char
		 */

		unsigned char* calc_Hash(unsigned char* random_n);
		/*
		 * @param[random_n] : random number
		 */
		
		void read_prvKey(const std::string& prvKeyfile);
		/*
		 * @param[prvKeyfile] : file containing the xApp prvKey
		 */

		unsigned char* generate_signature(unsigned char* input, size_t mdlen);
		/*
		 * @param[input]
		 * @param[mdlen]
		 * return unsigned char
		 */

		unsigned char* conc_msg(unsigned char* msg, unsigned char* signature_addr);
		/*
		 * @param[msg]  
		 * @param[signature_addr]
		 */

		void test_msg_gen(unsigned char* addr, const std::string& fileout);
		/*
		 * @param[addr]
		 * @param[fileout]
		 * return void
		 */

		unsigned char* msg_encrypt(unsigned char* msg_plain, long int msg_plain_len);
		/*
		 * @param[msg_plain]
		 * @param[msg_plain_len]
		 * return unsigned char
		 */


	private:
		EVP_PKEY *prvKey;

};



}
}

#endif
