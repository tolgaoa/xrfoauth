/*
 * Authentication challenge message processing
 *
 * Controller (RIC) of the Linux Foundation (LF) for distributing access tokens to xApps from an 
 * OAUTH 2.0 server using JSON web tokens as the execution method of the tokens
 *
 *
 * !file xrf_msg.cpp
 * \brief
 * \author: Sudip Maitra
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: smaitra@vt.edu
 */

#include "xrf_msg.hpp"

using namespace xrf::app;

extern xrf_msg* xrf_msg_inst;

void xrf_msg::print_debug(const std::string&str, unsigned char buf[], unsigned int len){
    if(DEBUG){
        std::cout << str;
            for(int i = 0; i < len; i++){
                printf("%02x",buf[i]);
            }
            printf("\n");
        }
}

void xrf_msg::write_debug(const std::string&str, unsigned char msg[], unsigned int msg_len){
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

unsigned char* xrf_msg::rsa_decrypt(unsigned char* cip_buf, long int cip_len){

    EVP_PKEY *prvKey;
    prvKey = EVP_PKEY_new();
    FILE* fp = fopen("prv_xrf", "r");
    if (!fp) spdlog::error("Could not open private key file");

    PEM_read_PrivateKey(fp,&prvKey,NULL,NULL);
    fclose(fp);

    EVP_PKEY_CTX *ctx;
    unsigned char* out;
    unsigned char* in = &cip_buf[0];
    size_t outlen, inlen = cip_len;

    ctx = EVP_PKEY_CTX_new(prvKey, NULL);
     if (!ctx) spdlog::error("Error 1");

     if (EVP_PKEY_decrypt_init(ctx) <= 0) spdlog::error("Error 2");

     if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) spdlog::error("Error 3");

     /* Determine buffer length */
     if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0) spdlog::error("Error 4");

     out = (unsigned char *)OPENSSL_malloc(outlen);

     if (!out) spdlog::error("Error 5");

     if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0) spdlog::error("Error 6");

     /* Encrypted data is outlen bytes written to buffer out */

    EVP_PKEY_free(prvKey);
    EVP_PKEY_CTX_free(ctx);
    return out;
}

void xrf_msg::prep_msg(unsigned char m_buf[], unsigned char sig_buf[], unsigned char msg_plain_1[], unsigned char msg_plain_2[]){

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

int xrf_msg::verify_sig(unsigned char* md_buf, unsigned char* sig_buf){

    EVP_PKEY *pubKey;
    pubKey = EVP_PKEY_new();
    FILE* fp = fopen("pub_xapp", "r");
    if (!fp) spdlog::error("Could not open public key file");


    PEM_read_PUBKEY(fp,&pubKey,NULL,NULL);
    fclose(fp);

    EVP_PKEY_CTX *ctx;
    unsigned char* md = &md_buf[0]; 
    unsigned char* sig= &sig_buf[0];
    size_t mdlen = SHA256_LENGTH, siglen = RSA_SIG_LEN;

    ctx = EVP_PKEY_CTX_new(pubKey, NULL /* no engine */);
    if (!ctx) spdlog::error("Error 1");

    if (EVP_PKEY_verify_init(ctx) <= 0) spdlog::error("Error 2");

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) spdlog::error("Error 3");

    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) spdlog::error("Error 4");

    /* Perform operation */
    int ret = EVP_PKEY_verify(ctx, sig, siglen, md, mdlen);

    if (ret == 1) spdlog::debug("Verification successful!");
    else if(ret == 0) spdlog::debug("Verification failed.");
    else spdlog::debug("Unspecified error.");

    EVP_PKEY_free(pubKey);
    EVP_PKEY_CTX_free(ctx);

    return ret;
}

int xrf_msg::final_verification(const std::string&rec_str, unsigned char m_buf[]){

    /*
                            Load ciphertext in from rec_str
    */
    int rec_str_len = rec_str.length();
    char rec_char_array[rec_str_len+1];
    strcpy(rec_char_array, rec_str.c_str());

    unsigned char cip_buf[FINAL_CIPHER_LEN];
    EVP_DecodeBlock(cip_buf, (unsigned char*)rec_char_array, rec_str_len);  

    print_debug("\nFinal Ciphertext:\n", cip_buf, FINAL_CIPHER_LEN);

    /*
                            Split the buffer in two for decryption
    */

    unsigned char cip_buf_1[RSA_ENC_LEN],cip_buf_2[RSA_ENC_LEN];
    for(int i = 0; i < RSA_ENC_LEN; i++){
        cip_buf_1[i]=cip_buf[i];
        cip_buf_2[i]=cip_buf[i+RSA_ENC_LEN];
    }

    print_debug("\nCiphertext_1:\n",cip_buf_1, RSA_ENC_LEN);
    print_debug("\nCiphertext_2:\n",cip_buf_2, RSA_ENC_LEN);

    /*
                            Decrypt ciphertext_1 and 2
    */

    unsigned char* plain_buf_1 = rsa_decrypt(cip_buf_1, RSA_ENC_LEN);
    unsigned char* plain_buf_2 = rsa_decrypt(cip_buf_2, RSA_ENC_LEN);
    print_debug("\nPlaintext_1\n", plain_buf_1, PLAIN_LEN);
    print_debug("\nPlaintext_2\n", plain_buf_2, PLAIN_LEN);
    write_debug("plaintext_1", plain_buf_1, PLAIN_LEN);
    write_debug("plaintext_2", plain_buf_2, PLAIN_LEN);

    /*
                            Extract m and sig
    */
    unsigned char sig_buf[RSA_SIG_LEN];
    prep_msg(m_buf, sig_buf, plain_buf_1, plain_buf_2);
    print_debug("\nmsg:\n",m_buf,RND_LENGTH);
    print_debug("\nsig:\n",sig_buf,RSA_SIG_LEN);
    write_debug("rnd.bin", m_buf, RND_LENGTH);
    write_debug("sig.bin", sig_buf, RSA_SIG_LEN);

    /*
                            Calculate hash of m : h(m)
    */
    unsigned char hm_buf[SHA256_LENGTH];
    SHA256(m_buf, RND_LENGTH, hm_buf);
    print_debug("\nHash(m):\n", hm_buf, SHA256_LENGTH);
    /*
                            Verify signature
    */
    int verify_result = verify_sig(hm_buf, sig_buf);
    return verify_result;
}

unsigned char* xrf_msg::gen_sig(unsigned char hm_buf[]){
    /*
                Generate Signature: E(PR_xrf, H(m))
    */
    spdlog::debug("Reading private key file");
    EVP_PKEY *prvKey;
    prvKey = EVP_PKEY_new();
    FILE* fp = fopen("prv_xrf", "r");
    if (!fp) spdlog::error("Could not open private key file");

    PEM_read_PrivateKey(fp,&prvKey,NULL,NULL);
    fclose(fp);

        unsigned char* md = &hm_buf[0]; 
        unsigned char* sig_buf=nullptr;

        size_t mdlen = SHA256_LENGTH, siglen;
        EVP_PKEY_CTX *ctx;
        ctx = EVP_PKEY_CTX_new(prvKey, NULL);

        if (!ctx) spdlog::error("Context init failed 1");

        if (EVP_PKEY_sign_init(ctx) <= 0) spdlog::error("Context init failed 2");
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) spdlog::error("RSA padding failed");
        if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) spdlog::error("Digest failed");
        if (EVP_PKEY_sign(ctx, NULL, &siglen, md, mdlen) <= 0) spdlog::error("Signing failed 1");

        sig_buf = (unsigned char *)OPENSSL_malloc(siglen);
        if(!sig_buf) spdlog::error("malloc failure");

        if (EVP_PKEY_sign(ctx, sig_buf, &siglen, md, mdlen) <= 0) spdlog::error("Signing failed 2 failure");

        unsigned char *sig_ptr = sig_buf;
        EVP_PKEY_free(prvKey);
        EVP_PKEY_CTX_free(ctx);
        return sig_ptr;
}

void xrf_msg::prep_msg_1(unsigned char m_buf[], unsigned char sig_buf[], unsigned char msg_plain_1[], unsigned char msg_plain_2[]){

        /*
                        msg = m || E(PU_xApp, H(m)) 
        */
        unsigned char msg_buf[MSG_BUFLEN];
        for(int i = 0; i < RND_LENGTH; i++){
                msg_buf[i] = m_buf[i];
        }

        for(int i = RND_LENGTH; i < MSG_BUFLEN; i++){
                msg_buf[i] = sig_buf[i-RND_LENGTH];
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

unsigned char* xrf_msg::rsa_encrypt(unsigned char* msg_plain, long int msg_plain_len){

    /*
                    Read PU_xApp from File
    */
    EVP_PKEY *pub_xrf;
    pub_xrf = EVP_PKEY_new();
    FILE* f_pub_xrf = fopen("pub_xapp", "r");
    if (!f_pub_xrf) spdlog::error("Could not open public key file");

    PEM_read_PUBKEY(f_pub_xrf,&pub_xrf,NULL,NULL);
    fclose(f_pub_xrf);

    EVP_PKEY_CTX *ctx_enc;
    unsigned char* msg_enc;
    size_t msg_enc_len;

    /*
    Encrypt MSG with PU_xrf
    */

    ctx_enc = EVP_PKEY_CTX_new(pub_xrf, NULL);
        if (!ctx_enc) spdlog::debug("Error 1");
        if (EVP_PKEY_encrypt_init(ctx_enc) <= 0) spdlog::error("Error 2");
        if (EVP_PKEY_CTX_set_rsa_padding(ctx_enc, RSA_PKCS1_OAEP_PADDING) <= 0) spdlog::error("Error 3");

        /* Determine buffer length */
        if (EVP_PKEY_encrypt(ctx_enc, NULL, &msg_enc_len, msg_plain, msg_plain_len) <= 0) spdlog::error("Error 4");

        msg_enc = (unsigned char *)OPENSSL_malloc(msg_enc_len);
        if (!msg_enc) spdlog::error("Error 5");
        if (EVP_PKEY_encrypt(ctx_enc, msg_enc, &msg_enc_len, msg_plain, msg_plain_len) <= 0) spdlog::error("Error 6");

    EVP_PKEY_free(pub_xrf);
    EVP_PKEY_CTX_free(ctx_enc);
    return msg_enc;
}

void xrf_msg::create_final_msg(std::string&str, unsigned char m_buf[]) {

    print_debug("\nm:\n", m_buf, RND_LENGTH);

    unsigned char hm_buf[SHA256_LENGTH];
    SHA256(m_buf, RND_LENGTH, hm_buf);
    print_debug("\nH(m):\n", hm_buf, SHA256_LENGTH);

    unsigned char *sig_buf = gen_sig(hm_buf);

    print_debug("\nSig:\n", sig_buf, RSA_SIG_LEN);
    write_debug("sig.bin", sig_buf, RSA_SIG_LEN);

    unsigned char msg_plain_1[PLAIN_LEN], msg_plain_2[PLAIN_LEN];
    prep_msg_1(m_buf, sig_buf, msg_plain_1, msg_plain_2);

    print_debug("\nmsg_plain_1:\n", msg_plain_1, PLAIN_LEN);
    print_debug("\nmsg_plain_2:\n", msg_plain_2, PLAIN_LEN);

    unsigned char* msg_enc_1 = rsa_encrypt(&msg_plain_1[0], PLAIN_LEN);
    print_debug("\nCiphertext_1:\n", msg_enc_1, RSA_ENC_LEN);
    write_debug("ciphertext_1", msg_enc_1, RSA_SIG_LEN);

    unsigned char* msg_enc_2 = rsa_encrypt(&msg_plain_2[0], PLAIN_LEN);
    print_debug("\nCiphertext_2:\n", msg_enc_2, RSA_ENC_LEN);
    write_debug("ciphertext_2", msg_enc_2, RSA_SIG_LEN);

    unsigned char final_cipher_buf[FINAL_CIPHER_LEN];
    
    for(int i = 0; i < RSA_ENC_LEN; i++){
        final_cipher_buf[i] = msg_enc_1[i];
        final_cipher_buf[i+RSA_ENC_LEN] = msg_enc_2[i];
    }   

    print_debug("\nFinal Ciphertext:\n", final_cipher_buf, FINAL_CIPHER_LEN);
    write_debug("finalciphertext", final_cipher_buf, FINAL_CIPHER_LEN);

    char encodedData[ENCODE_DATA_LEN];
    int encoded_data_len = EVP_EncodeBlock((unsigned char*)encodedData, final_cipher_buf, FINAL_CIPHER_LEN);
    
    for(int i=0; i < encoded_data_len; i++){
        str.push_back(encodedData[i]);
    }
}


