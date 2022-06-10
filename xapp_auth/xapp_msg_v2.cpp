#include "xapp_msg.hpp"

unsigned char * rsa_encrypt(unsigned char*, long int);

int main(){

	/*
													Generate m[128]
	*/
	printf("\nGenerating m...\n");
	unsigned char m_buf[RND_LENGTH];
	int m_rc = RAND_bytes(m_buf, sizeof(m_buf));
	if(m_rc != 1){
		printf("\nRandom number generation failed\n");
		return 0;
	}

	printf("\nm:\n");
	for(int i = 0; i < RND_LENGTH; i++){
		printf("%02x",m_buf[i]);
	}
	printf("\n");

	/*
													Calculate H(m1)
	*/
	unsigned char hm_buf[SHA256_LENGTH];
	size_t n = (sizeof(m_buf)/sizeof(m_buf[0]));
	SHA256(m_buf, n, hm_buf);
	printf("\nH(m):\n");
	for(int i = 0; i < SHA256_LENGTH; i++){
		printf("%02x",hm_buf[i]);
	}
	printf("\n");

	/*
													Read Public/Private Key from File
	*/
    printf("\nReading Private Key File...\n");
    EVP_PKEY *prvKey;
    prvKey = EVP_PKEY_new();
    FILE* fp = fopen("prv_xapp", "r");
    if (!fp) {
        std::cout << "Could not open private key file";
        return 0;
    }

    PEM_read_PrivateKey(fp,&prvKey,NULL,NULL);
    fclose(fp);

	/*
													Generate Signature
	*/
	printf("\nSignature:\n");
	unsigned char* md = &hm_buf[0]; 
	unsigned char* sig_buf=nullptr;

	size_t mdlen = SHA256_LENGTH, siglen;
	EVP_PKEY_CTX *ctx;
	ctx = EVP_PKEY_CTX_new(prvKey, NULL);

	if (!ctx){
		std::cout << "Context init failed 1" << std::endl;
	}

	if (EVP_PKEY_sign_init(ctx) <= 0){
		std::cout << "Context init failed 2" << std::endl;
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0){
		std::cout << "RSA padding failed" << std::endl;
	}

	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0){
		std::cout << "Digest failed" << std::endl;
	}

	if (EVP_PKEY_sign(ctx, NULL, &siglen, md, mdlen) <= 0){
		std::cout << "Signing failed 1" << std::endl;
	}

	sig_buf = (unsigned char *)OPENSSL_malloc(siglen);

	if(!sig_buf){
		std::cout << "malloc failure" << std::endl;
	}

	if (EVP_PKEY_sign(ctx, sig_buf, &siglen, md, mdlen) <= 0){
		std::cout << "Signing failed 2 failure" << std::endl;
	}
	else{
		for(int i = 0; i<siglen; i++){
			printf("%02x",sig_buf[i]);
		}
		printf("\n");
	}

	std::ofstream sigFile("sig.bin");
	if(sigFile.is_open()){
		for(int i = 0; i < siglen; i++){
			sigFile << sig_buf[i];
		}
		sigFile.close();
	}

	EVP_PKEY_free(prvKey);
	EVP_PKEY_CTX_free(ctx);

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

	printf("\nmsg:\n");
	for(int i = 0; i < MSG_BUFLEN; i++){
		printf("%02x",msg_buf[i]);
	}
	printf("\n");

	unsigned char msg_plain_1[PLAIN_LEN], msg_plain_2[PLAIN_LEN];
	for(int i = 0; i < PLAIN_LEN; i++){
		msg_plain_1[i] = msg_buf[i];
	}

	for(int i = 0; i < MSG_BUFLEN; i++){
		msg_plain_2[i] = msg_buf[i+PLAIN_LEN];
	}

	std::ofstream plaintextFile("plaintext");
	if(plaintextFile.is_open()){
		for(int i = 0; i < MSG_BUFLEN; i++){
			plaintextFile << msg_buf[i];
		}
		plaintextFile.close();
	}

	/*
													E(PU_XRF,msg)
	*/
    unsigned char* msg_enc_1 = rsa_encrypt(&msg_plain_1[0], PLAIN_LEN);
    printf("\nCiphertext_1:\n");
    for(int i = 0; i < RSA_ENC_LEN; i++){
        printf("%02x",msg_enc_1[i]);
    }
    printf("\n");

    std::ofstream ciphertext_1("ciphertext_1");
    if(ciphertext_1.is_open()){
        for(int i = 0; i < RSA_ENC_LEN; i++){
            ciphertext_1 << msg_enc_1[i];
        }
        ciphertext_1.close();
    }

    unsigned char* msg_enc_2 = rsa_encrypt(&msg_plain_2[0], PLAIN_LEN);
    printf("\nCiphertext_2:\n");
    for(int i = 0; i < RSA_ENC_LEN; i++){
        printf("%02x",msg_enc_2[i]);
    }
    printf("\n");

    std::ofstream ciphertext_2("ciphertext_2");
    if(ciphertext_2.is_open()){
        for(int i = 0; i < RSA_ENC_LEN; i++){
            ciphertext_2 << msg_enc_2[i];
        }
        ciphertext_2.close();
    }

    return 0;
}

unsigned char * rsa_encrypt(unsigned char* msg_plain, long int msg_plain_len){

	/*
													Read PU_XRF from File
	*/

    printf("\nReading Public Key File...\n");
    EVP_PKEY *pub_xrf;
    pub_xrf = EVP_PKEY_new();
    FILE* f_pub_xrf = fopen("pub_xrf", "r");
    if (!f_pub_xrf) {
        std::cout << "Could not open public key file";
        return 0;
    }

    PEM_read_PUBKEY(f_pub_xrf,&pub_xrf,NULL,NULL);
    fclose(f_pub_xrf);

    EVP_PKEY_CTX *ctx_enc;
    unsigned char* msg_enc;
    size_t msg_enc_len;

    /*
    												Encrypt MSG with PU_XRF
    */

    ctx_enc = EVP_PKEY_CTX_new(pub_xrf, NULL);
	if (!ctx_enc){
		std::cout << "Error 1" << std::endl;
		return 0;
	}

	if (EVP_PKEY_encrypt_init(ctx_enc) <= 0){
		std::cout << "Error 2" << std::endl;
		return 0;
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx_enc, RSA_PKCS1_OAEP_PADDING) <= 0){
		std::cout << "Error 3" << std::endl;
		return 0;
	}

	/* Determine buffer length */
	if (EVP_PKEY_encrypt(ctx_enc, NULL, &msg_enc_len, msg_plain, msg_plain_len) <= 0){
		std::cout << "Error 4" << std::endl;
		return 0;
	}

	msg_enc = (unsigned char *)OPENSSL_malloc(msg_enc_len);

	if (!msg_enc){
		std::cout << "Error 5" << std::endl;
		return 0;
	}

	if (EVP_PKEY_encrypt(ctx_enc, msg_enc, &msg_enc_len, msg_plain, msg_plain_len) <= 0){
		std::cout << "Error 6" << std::endl;
		return 0;
	}

    EVP_PKEY_free(pub_xrf);
    EVP_PKEY_CTX_free(ctx_enc);
    return msg_enc;
}
