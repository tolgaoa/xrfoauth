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

//TA:--------------Converted functions into class functions------------------
//-------------------Created create_final_msg function-----------------------
//---------------------------------------------------------------------------


#include "xapp_msg.hpp"

using namespace xrf::app;

extern xapp_msg* xapp_msg_inst;


void xapp_msg::print_debug(const std::string&str, unsigned char buf[], unsigned int len){
    if(DEBUG){
        std::cout << str;
            for(int i = 0; i < len; i++){
                printf("%02x",buf[i]);
            }
            printf("\n");
        }
}

void xapp_msg::write_debug(const std::string&str, unsigned char msg[], unsigned int msg_len){
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


void xapp_msg::gen_rand(unsigned char rand_buf[]){
	spdlog::debug("Generating random number");
        int rc = RAND_bytes(rand_buf, RND_LENGTH);
        if(rc != 1) spdlog::debug("Random number generation failed");
}

//TA:-----------ADDED this------------------------------------
void xapp_msg::calc_hash(unsigned char m_buf[], unsigned char hm_buf[]){
        size_t n = RND_LENGTH;
        SHA256(m_buf, n, hm_buf);
}
//------------------------------------------------------------

unsigned char* xapp_msg::gen_sig(unsigned char hm_buf[]){
        /*
	Generate Signature: E(PR_xApp, H(m))
        */
	spdlog::debug("Reading private key file");
	EVP_PKEY *prvKey;
	prvKey = EVP_PKEY_new();
	FILE* fp = fopen("prv_xapp", "r");
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

void xapp_msg::prep_msg(unsigned char m_buf[], unsigned char sig_buf[], unsigned char msg_plain_1[], unsigned char msg_plain_2[]){

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


	/*spdlog::debug("msg:");
	for(int i = 0; i < MSG_BUFLEN; i++){
		spdlog::debug("%02x",msg_buf[i]);
	}*/

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

unsigned char* xapp_msg::rsa_encrypt(unsigned char* msg_plain, long int msg_plain_len){

	/*
	Read PU_xrf from File
	*/
	EVP_PKEY *pub_xrf;
	pub_xrf = EVP_PKEY_new();
	FILE* f_pub_xrf = fopen("pub_xrf", "r");
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

std::string xapp_msg::create_final_msg(unsigned char final_cipher_buf[FINAL_CIPHER_LEN]) {
	unsigned char m_buf[RND_LENGTH];
	gen_rand(m_buf);
	//spdlog::debug("\nm:\n", m_buf, RND_LENGTH);

	unsigned char hm_buf[SHA256_LENGTH];
	SHA256(m_buf, RND_LENGTH, hm_buf);
	//print_debug("\nH(m):\n", hm_buf, SHA256_LENGTH);

	unsigned char *sig_buf = gen_sig(hm_buf);

	print_debug("\nSig:\n", sig_buf, RSA_SIG_LEN);
	write_debug("sig.bin", sig_buf, RSA_SIG_LEN);

	unsigned char msg_plain_1[PLAIN_LEN], msg_plain_2[PLAIN_LEN];
	prep_msg(m_buf, sig_buf, msg_plain_1, msg_plain_2);

	print_debug("\nmsg_plain_1:\n", msg_plain_1, PLAIN_LEN);
	print_debug("\nmsg_plain_2:\n", msg_plain_2, PLAIN_LEN);

	unsigned char* msg_enc_1 = rsa_encrypt(&msg_plain_1[0], PLAIN_LEN);
	print_debug("\nCiphertext_1:\n", msg_enc_1, RSA_ENC_LEN);
	write_debug("ciphertext_1", msg_enc_1, RSA_SIG_LEN);

    	unsigned char* msg_enc_2 = rsa_encrypt(&msg_plain_2[0], PLAIN_LEN);
    	print_debug("\nCiphertext_2:\n", msg_enc_2, RSA_ENC_LEN);
    	write_debug("ciphertext_2", msg_enc_2, RSA_SIG_LEN);

	//unsigned char final_cipher_buf[FINAL_CIPHER_LEN];
	
	for(int i = 0; i < RSA_ENC_LEN; i++){
		final_cipher_buf[i] = msg_enc_1[i];
		final_cipher_buf[i+RSA_ENC_LEN] = msg_enc_2[i];
	}	

	print_debug("\nFinal Ciphertext:\n", final_cipher_buf, FINAL_CIPHER_LEN);
	write_debug("finalciphertext", final_cipher_buf, FINAL_CIPHER_LEN);
	
	std::string str;

	char encodedData[ENCODE_DATA_LEN];
	int encoded_data_len = EVP_EncodeBlock((unsigned char*)encodedData, final_cipher_buf, FINAL_CIPHER_LEN);
	//std::cout << encodedData << std::endl;
	
	for(int i=0; i < encoded_data_len; i++){
		str.push_back(encodedData[i]);
	}

	spdlog::debug("The string to be sent is:");
	spdlog::debug(str);

	return str;
}


