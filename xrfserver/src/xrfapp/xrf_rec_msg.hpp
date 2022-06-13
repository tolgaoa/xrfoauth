/*
 * xrf processing after receiving the challenge from xApp for authentication
 *
 *
 * ! file xrf_rec_msg.hpp
 * \brief
 * \author: Sudip Maitra
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: smaitra@vt.edu
*/

#ifndef FILE_XRF_REC_MSG_HPP_SEEN
#define FILE_XRF_REC_MSG_HPP_SEEN


#include <iostream>
#include <fstream>
#include <openssl/pem.h> 
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <cstdio>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define RND_LENGTH 128
#define SHA256_LENGTH 32
#define MSG_BUFLEN 640
#define PLAIN_LEN 320
#define RSA_SIG_LEN 512
#define RSA_ENC_LEN 512
#define FINAL_CIPHER_LEN 1024

#define DEBUG 1
#define WRITE_FILE 0

namespace xrf{
namespace app{

class xrf_rec_msg{
    public:
        explicit xrf_rec_msg();
        xrf_rec_msg(xrf_rec_msg const&) = delete;
        virtual ~xrf_rec_msg();
        void operator=(xrf_rec_msg const&) = delete;

        void print_debug(const std::string&, unsigned char*, unsigned int);
        void write_debug(const std::string&, unsigned char*, unsigned int);
        unsigned char* rsa_decrypt(unsigned char*, long int);
        void prep_msg(unsigned char*, unsigned char*, unsigned char*, unsigned char*);
        void verify_sig(unsigned char*, unsigned char*);
};
} // app namespace defined
} // xrf namespace defined












#endif
