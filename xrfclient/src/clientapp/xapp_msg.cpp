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

void print_debug(const std::string&str, unsigned char buf[], unsigned int len){
    if(DEBUG){
        std::cout << str;
            for(int i = 0; i < len; i++){
                printf("%02x",buf[i]);
            }
            printf("\n");
        }
}

void write_debug(const std::string&str, unsigned char msg[], unsigned int msg_len){
        if(WRITE_FILE){
            std::ofstream file(str);
            if(file.is_open()){
                for(int i = 0; i < msg_len; i++){
                    file << msg[i];
                }
                file.close();
            }
        }
}

void gen_rand(unsigned char rand_buf[]){
        std::cout << "\nGenerating Random Number" << std::endl;
        int rc = RAND_bytes(rand_buf, RND_LENGTH);
        if(rc != 1) std::cout << "\nRandom number generation failed" << std::endl;
}

unsigned char* gen_sig(unsigned char hm_buf[]){
        /*
                                                                                                        Generate Signature: E(PR_xApp, H(m))
        */
    std::cout << "\nReading Private Key File" << std::endl;
    EVP_PKEY *prvKey;
    prvKey = EVP_PKEY_new();
    FILE* fp = fopen("prv_xapp", "r");
    if (!fp) std::cout << "Could not open private key file" << std::endl;

    PEM_read_PrivateKey(fp,&prvKey,NULL,NULL);
    fclose(fp);

        unsigned char* md = &hm_buf[0]; 
        unsigned char* sig_buf=nullptr;

        size_t mdlen = SHA256_LENGTH, siglen;
        EVP_PKEY_CTX *ctx;
        ctx = EVP_PKEY_CTX_new(prvKey, NULL);

        if (!ctx) std::cout << "Context init failed 1" << std::endl;

        if (EVP_PKEY_sign_init(ctx) <= 0) std::cout << "Context init failed 2" << std::endl;

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) std::cout << "RSA padding failed" << std::endl;

        if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) std::cout << "Digest failed" << std::endl;

        if (EVP_PKEY_sign(ctx, NULL, &siglen, md, mdlen) <= 0) std::cout << "Signing failed 1" << std::endl;

        sig_buf = (unsigned char *)OPENSSL_malloc(siglen);

        if(!sig_buf) std::cout << "malloc failure" << std::endl;

        if (EVP_PKEY_sign(ctx, sig_buf, &siglen, md, mdlen) <= 0) std::cout << "Signing failed 2 failure" << std::endl;

        unsigned char *sig_ptr = sig_buf;

        EVP_PKEY_free(prvKey);
        EVP_PKEY_CTX_free(ctx);
        return sig_ptr;
}

void prep_msg(unsigned char m_buf[], unsigned char sig_buf[], unsigned char msg_plain_1[], unsigned char msg_plain_2[]){
        /*
                                                                                                         msg = m || E(PR_xAPP, H(m)) 
        */

        unsigned char msg_buf[MSG_BUFLEN];
        for(int i = 0; i < RND_LENGTH; i++){
                msg_buf[i] = m_buf[i];
        }

        for(int i = RND_LENGTH; i < MSG_BUFLEN; i++){
                msg_buf[i] = sig_buf[i-RND_LENGTH];
        }


        if(DEBUG){
                printf("\nmsg:\n");
                for(int i = 0; i < MSG_BUFLEN; i++){
                        printf("%02x",msg_buf[i]);
                }
                printf("\n");                   
        }

        if(WRITE_FILE){
                std::ofstream plaintextFile("plaintext");
                if(plaintextFile.is_open()){
                        for(int i = 0; i < MSG_BUFLEN; i++){
                                plaintextFile << msg_buf[i];
                        }
                        plaintextFile.close();
                }       
        }

        for(int i = 0; i < PLAIN_LEN; i++){
                msg_plain_1[i] = msg_buf[i];
                msg_plain_2[i] = msg_buf[i+PLAIN_LEN];
        }
}

unsigned char* rsa_encrypt(unsigned char* msg_plain, long int msg_plain_len){

        /*
                                                                                                        Read PU_xrf from File
        */
    EVP_PKEY *pub_xrf;
    pub_xrf = EVP_PKEY_new();
    FILE* f_pub_xrf = fopen("pub_xrf", "r");
    if (!f_pub_xrf) std::cout << "Could not open public key file";

    PEM_read_PUBKEY(f_pub_xrf,&pub_xrf,NULL,NULL);
    fclose(f_pub_xrf);

    EVP_PKEY_CTX *ctx_enc;
    unsigned char* msg_enc;
    size_t msg_enc_len;

    /*
                                                                                                Encrypt MSG with PU_xrf
    */

    ctx_enc = EVP_PKEY_CTX_new(pub_xrf, NULL);
        if (!ctx_enc) std::cout << "Error 1" << std::endl;

        if (EVP_PKEY_encrypt_init(ctx_enc) <= 0) std::cout << "Error 2" << std::endl;


        if (EVP_PKEY_CTX_set_rsa_padding(ctx_enc, RSA_PKCS1_OAEP_PADDING) <= 0) std::cout << "Error 3" << std::endl;

        /* Determine buffer length */
        if (EVP_PKEY_encrypt(ctx_enc, NULL, &msg_enc_len, msg_plain, msg_plain_len) <= 0) std::cout << "Error 4" << std::endl;

        msg_enc = (unsigned char *)OPENSSL_malloc(msg_enc_len);

        if (!msg_enc) std::cout << "Error 5" << std::endl;

        if (EVP_PKEY_encrypt(ctx_enc, msg_enc, &msg_enc_len, msg_plain, msg_plain_len) <= 0) std::cout << "Error 6" << std::endl;

    EVP_PKEY_free(pub_xrf);
    EVP_PKEY_CTX_free(ctx_enc);
    return msg_enc;
}

