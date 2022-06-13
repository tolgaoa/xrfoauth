/*
 * xrf processing after receiving the challenge from xApp for authentication
 *
 *
 *
 * ! file xrf_rec_msg.cpp
 * \brief
 * \author: Sudip Maitra
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: smaitra@vt.edu
*/

#include "xrf_rec_msg.hpp"

using namespace xrf::app;

extern xrf_rec_msg* xapp_rec_msg_inst;

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

unsigned char* rsa_decrypt(unsigned char* cip_buf, long int cip_len){

    EVP_PKEY *prvKey;
    prvKey = EVP_PKEY_new();
    FILE* fp = fopen("prv_xrf", "r");
    if (!fp) std::cout << "Could not open private key file";

    PEM_read_PrivateKey(fp,&prvKey,NULL,NULL);
    fclose(fp);

    EVP_PKEY_CTX *ctx;
    unsigned char* out;
    unsigned char* in = &cip_buf[0];
    size_t outlen, inlen = cip_len;

    ctx = EVP_PKEY_CTX_new(prvKey, NULL);
     if (!ctx) std::cout << "Error 1" << std::endl;

     if (EVP_PKEY_decrypt_init(ctx) <= 0) std::cout << "Error 2" << std::endl;

     if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) std::cout << "Error 3" << std::endl;

     /* Determine buffer length */
     if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0) std::cout << "Error 4" << std::endl;

     out = (unsigned char *)OPENSSL_malloc(outlen);

     if (!out) std::cout << "Error 5" << std::endl;

     if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0) std::cout << "Error 6" << std::endl;

     /* Encrypted data is outlen bytes written to buffer out */

    EVP_PKEY_free(prvKey);
    EVP_PKEY_CTX_free(ctx);
    return out;
}

void prep_msg(unsigned char m_buf[], unsigned char sig_buf[], unsigned char msg_plain_1[], unsigned char msg_plain_2[]){

    for(int i = 0; i < RND_LENGTH; i++){
        m_buf[i] = msg_plain_1[i];
    }

    for(int i = RND_LENGTH; i < PLAIN_LEN; i++){
        sig_buf[i-RND_LENGTH] = msg_plain_1[i];
    }

    for(int i = 0; i < PLAIN_LEN; i++){
        sig_buf[i+(PLAIN_LEN-RND_LENGTH)] = msg_plain_2[i];
    }
}

void verify_sig(unsigned char* md_buf, unsigned char* sig_buf){

    EVP_PKEY *pubKey;
    pubKey = EVP_PKEY_new();
    FILE* fp = fopen("pub_xapp", "r");
    if (!fp) std::cout << "Could not open public key file" << std::endl;


    PEM_read_PUBKEY(fp,&pubKey,NULL,NULL);
    fclose(fp);

    EVP_PKEY_CTX *ctx;
    unsigned char* md = &md_buf[0]; 
    unsigned char* sig= &sig_buf[0];
    size_t mdlen = SHA256_LENGTH, siglen = RSA_SIG_LEN;

    ctx = EVP_PKEY_CTX_new(pubKey, NULL /* no engine */);
    if (!ctx) std::cout << "Error 1" << std::endl;

    if (EVP_PKEY_verify_init(ctx) <= 0) std::cout << "Error 2" << std::endl;

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) std::cout << "Error 3" << std::endl;

    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) std::cout << "Error 4" << std::endl;

    /* Perform operation */
    int ret = EVP_PKEY_verify(ctx, sig, siglen, md, mdlen);

    if (ret == 1){
        std::cout << "\nVerification successful" << std::endl; 
    }
    else if(ret == 0){
        std::cout << "\nVerification failed" << std::endl;
    }
    else{
        std::cout << "\nUnspecified error" << std::endl;
    }
    EVP_PKEY_free(pubKey);
    EVP_PKEY_CTX_free(ctx);
}

