#include "xapp_msg.hpp"

int main(){
	/*
													Read N[128] from rnd.bin [N = xApp ID]
	*/
	unsigned char N_buf[RND_LENGTH];
	int N_rc = RAND_bytes(N_buf, sizeof(N_buf));
	if(N_rc != 1){
		printf("\nRandom number generation failed\n");
		return 0;
	}

    printf("\nReading N from File...\n");
    std::ifstream rndFile ("rnd.bin", std::ifstream::binary);
    char * buffer = new char [RND_LENGTH];
    rndFile.read (buffer, RND_LENGTH);
    rndFile.close();

    for(int i = 0; i < RND_LENGTH; i++){
        N_buf[i] = *buffer;
        buffer++;
    }

	printf("\nN:\n");
	for(int i = 0; i < RND_LENGTH; i++){
		printf("%02x",N_buf[i]);
	}
	printf("\n");

	/*
													Generate R1[128]
	*/
	printf("\nGenerating R1...\n");
	unsigned char R1_buf[RND_LENGTH];
	int R1_rc = RAND_bytes(R1_buf, sizeof(R1_buf));
	if(R1_rc != 1){
		printf("\nRandom number generation failed\n");
		return 0;
	}

	printf("\nR1:\n");
	for(int i = 0; i < RND_LENGTH; i++){
		printf("%02x",R1_buf[i]);
	}
	printf("\n");

	/*
													Calculate m1 = N^R1
	*/
	printf("\nCalculate m1=N^R1...\n");
	unsigned char m1_buf[RND_LENGTH];
	std::copy_n(N_buf, RND_LENGTH, m1_buf);
	for(int i = 0; i < RND_LENGTH; i++){
		m1_buf[i] ^= R1_buf[i];
	}
	printf("\nm1:\n");
	for(int i = 0; i < RND_LENGTH; i++){
		printf("%02x",m1_buf[i]);
	}
	printf("\n");

	/*
													Calculate H(m1)
	*/
	unsigned char hm1_buf[SHA256_LENGTH];
	size_t n = (sizeof(m1_buf)/sizeof(m1_buf[0]));
	SHA256(m1_buf, n, hm1_buf);
	printf("\nH(m1):\n");
	for(int i = 0; i < SHA256_LENGTH; i++){
		printf("%02x",hm1_buf[i]);
	}
	printf("\n");

	/*
													msg1 = H(m1) || R1
	*/
	unsigned char msg1_buf[MS1_BUFLEN];
	for(int i = 0; i < SHA256_LENGTH; i++){
		msg1_buf[i] = hm1_buf[i];
	}

	for(int i = SHA256_LENGTH; i < MS1_BUFLEN; i++){
		msg1_buf[i] = R1_buf[i-SHA256_LENGTH];
	}

	printf("\nmsg1:\n");
	for(int i = 0; i < MS1_BUFLEN; i++){
		printf("%02x",msg1_buf[i]);
	}
	printf("\n");


	/*
													*********msg1_enc = Encrypt msg1 with xApp's private key*********
																				START
	*/

	/*
															Read Public/Private Key from File
	*/
    printf("\nReading Private Key File...\n");
    EVP_PKEY *prvKey;
    prvKey = EVP_PKEY_new();
    FILE* fp = fopen("prv_key", "r");
    if (!fp) {
        std::cout << "Could not open private key file";
        return 0;
    }

    PEM_read_PrivateKey(fp,&prvKey,NULL,NULL);
    fclose(fp);

	/*
													*********msg1_enc = Encrypt msg1 with xApp's private key*********
																				END
	*/



	/*
													ms2 = N || msg1_enc 
	*/



	/*
													msg2_enc = Encrypt msg2 with XRF's public key
	*/

	return 0;
}