/*
 * Authentication challenge message processing on server (xrf) side
 *
 * Controller (RIC) of the Linux Foundation (LF) for distributing access tokens to xApps from an 
 * OAUTH 2.0 server using JSON web tokens as the execution method of the tokens
 *
 *
 * ! file xrf_msg.hpp
 * \brief
 * \author: Sudip Maitra
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: smaitra@vt.edu
 */

#ifndef FILE_XRF_MSG_HPP_SEEN
#define FILE_XRF_MSG_HPP_SEEN

#include <iostream>
#include <fstream>
#include <openssl/pem.h> 
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
#define FINAL_CIPHER_LEN 1024
#define ENCODE_DATA_LEN 1369

#define DEBUG 0
#define WRITE_FILE 0


namespace xrf{
namespace app{
    class xrf_msg{
        public:
            explicit xrf_msg();
            xrf_msg(xrf_msg const&) = delete;
            virtual ~xrf_msg();
            void operator=(xrf_msg const&) = delete;

            void print_debug(const std::string&, unsigned char*, unsigned int);
            /*
             * @param[string] : string
             * @param[debug_msg] : pointer to debug msg array
             * @param[debug_msg_len] : debug msg length
             */
            void write_debug(const std::string&, unsigned char*, unsigned int);
            /*
             * @param[stirng] : string
             * @param[write_msg] : address of the msg to be written to file
             * @param[write_msg_len] : length of the msg to be written to file
             */

            unsigned char* rsa_decrypt(unsigned char* cip_buf, long int cip_len);
            /*
             * @param[cip_buf] : cipher buffer
             * @param[cip_len] : cipher length
             * return plaintext pointer
             */

            void prep_msg(unsigned char m_buf[], unsigned char sig_buf[], unsigned char msg_plain_1[], unsigned char msg_plain_2[]);
            /*
             * extracts and prepares the message and signature from the plaintext 1 & 2 for verification
             * @param[m_buf] : plaintext to be populated by the function
             * @param[sig_buf] : signature to be populated by the funciton
             * @param[msg_plain_1] : the half of the message after decryption
             * @param[msg_plain_2] : the other half of the message after decryption
             */

            int verify_sig(unsigned char* md_buf, unsigned char* sig_buf);
            /*
             * verification of signature
             * @param[md_buf] : hash of m
             * @param[sig_buf] : signature to be verified
             * return 1 if successful, 0 if unsuccessful, something else for unexpected errors
             */

            int final_verification(const std::string&rec_str, unsigned char m_buf[]);
            /*
             * final verification function being called from xrf_main
             * @param[rec_str] : string received from xapp, passed to this funciton from xrf_main
             * @param[m_buf] : funciton updates this buffer with the plaintext challenge sent by xApp
             * return 1 if successful, 0 if unsuccessful, something else for unexpected errors
             */

            unsigned char* gen_sig(unsigned char hm_buf[]);
            /*
             * @param[hm_buf] : hash of random number
             * return signature buffer pointer
             */

            void prep_msg_1(unsigned char m_buf[], unsigned char sig_buf[], unsigned char msg_plain_1[], unsigned char msg_plain_2[]);
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

            void create_final_msg(std::string&str, unsigned char m_buf[]);
            /*
             * Create final msg for sending out
             * @param[str] : str will be updated with the final msg by the function
             * @param[rec_msg] : pass in the received challenege 
             */
    };
}
}

#endif
