#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include "params.h"                                                             
#include "poly.h"
#include "polyvec.h"
#include "ntt.h"                                                                
#include "reduce.h"                                                             
#include "cbd.h"                                                                
#include "symmetric.h"                                                          
#include "indcpa.h" 
#include <string.h>
#include "api.h"

/*
 * Helper function that helps recover the coefficient of the secret key given
 * the integer h for the kyber_1024 attack.  
 */
int check_1024(int h)
{
	switch (h) {
		case 7:
			return -2;
		case 8:
			return -1;
		case 9:
			return 0;
		case 10:
			return 1;
		case 11:
			return 2;
	}
	return 10;
}

/*
 * Helper function that helps recover the coefficient of the secret key given
 * the integer h for the kyber_768 attack.  
 */
int check_768(int h)
{
	switch (h) {
		case 3:
			return -2;
		case 4:
			return -1;
		case 5:
			return 0;
		case 6:
			return 1;
		case 7:
			return 2;
	}
	return 10;
}

/*
 * Helper function that helps recover the coefficient of the secret key given
 * the integer h for the kyber_512 attack.  
 */
int check_512(int h, int h1)
{
	switch (h) {
		case 1:
			return -2;
		case 2:
			return -1;
		case 3:
			return 0;
		case 4:
			if (h1 == 1) {
				return 2;
			} else if (h1 == 2) {
				return 1;
			}
			break;
		case 5:
			if (h1 == 1) {
				return 2;
			}
	}
	return 10;
}

/*
 * De-serialize the bytes representing the secret key into a vector of 
 * polynomials.
 */
static void unpack_sk(polyvec *sk, const unsigned char *packedsk)
{
  	polyvec_frombytes(sk, packedsk);
}

/*
 * De-serialize the ciphertext c into a vector of polynomials b and a 
 * polynomial v.
 */
static void unpack_ciphertext(polyvec *b, poly *v, const unsigned char *c)
{
  	polyvec_decompress(b, c);
  	poly_decompress(v, c+KYBER_POLYVECCOMPRESSEDBYTES);
}

/*
 * Oracle that tells wether given a certain message m, the computed message
 * mp's first bit is 1.
 */
void oracle_m(unsigned char *m, const unsigned char *c, const unsigned char *sk)                     
{                                                                               
  	polyvec bp, skpv;                                                             
  	poly v, mp;                                                                   
    
	// Unpack the ciphertext c1 and c2 into Pb (bp) and v
  	unpack_ciphertext(&bp, &v, c);                                                
   
   	// We can see that bp[0] = round(KYBER_Q / 32)
	// And v[0] = round(KYBER_Q * h / 32)
  	printf("\n\nv.coeffs[0] = %d\n", v.coeffs[0]);                                                                              
	printf("pb.coeffs[0] = %d\n", bp.vec[0].coeffs[0]);
	
	// Unpack the secret key to get access to its coefficients
	unpack_sk(&skpv, sk);

	// For debugging purposes, print the first coefficient from the first
	// polynomial of the secret key
	printf("sk.vec[0].coeffs[0] = %d  ", skpv.vec[0].coeffs[0]);	
	printf("\n");

  	
	// Compute mp = v - sk * bp
	polyvec_pointwise_acc(&mp, &skpv, &bp);
	poly_sub(&mp, &v, &mp);                                                       
 
 	// Debugging print of the first coefficient of mp
	printf("Before reduce mp.coeffs[0] = %d\n", mp.coeffs[0]); 

	// Apply reduction to the coefficients of the mp
 	poly_reduce(&mp);                                                             
  	printf("After reduce mp.coeffs[0] = %d\n", mp.coeffs[0]);                        
  	
	/*float aux = mp.coeffs[0];
	aux *= 2;
	aux /= KYBER_Q;
	int aux_int = aux;
	printf("%d %f\n", aux_int, aux);
	float diff = aux - aux_int;
	if (diff >= 0.5) {
		return 1;
	}
	return 0;
	*/

	// Convert polynomial message mp to byte stream
	poly_tomsg(m, &mp);                                                           
} 

/*
 * Key recovery attack for Kyber-1024. 
 * sk_a is the actual secret key of Alice and sp is the secret key recovered =
 * by the attack.
 */
void key_recovery_kyber1024_v1(unsigned char *sp, unsigned char *sk_a)
{
	// First create a 32 bytes message (256 bits) where the first bit = 1 and
 	// al the other bits = 0
	unsigned char m[32];
	memset(m, 0, 32 * sizeof(unsigned char));
	m[0] |= (1 << 7);

	// Compute the round(KYBER_Q / 32) value that will be needed in the future
	float float_value = KYBER_Q / 32.0;
	float int_value = KYBER_Q / 32; 
	float diff = float_value - int_value;
	int value = (int) int_value;
	if (diff >= 0.5) {
		value += 1;
	} 

	int vec_idx;

	// Target one of the 4 polynomials of the secret key
	for (int i = 0; i < 4; ++i) {
		// Target the kth coefficient of the polynomial
		for (int k = 0; k < 256; ++k) {
			
			// Compute Bob's public key as suggested by the attack
			polyvec pb;
			memset(&pb, 0, sizeof(polyvec));
	
			if (k == 0) {
				for (vec_idx = 0; vec_idx < KYBER_K; ++vec_idx) {
					pb.vec[vec_idx].coeffs[k] = value;
				}
			} else {
				for (vec_idx = 0; vec_idx < KYBER_K; ++vec_idx) {
					pb.vec[vec_idx].coeffs[256 - k] = 0;
					pb.vec[vec_idx].coeffs[256 - k] -= value;
				}
			}
			
			// Compute the ciphertext c = (c1 || c2) as suggested by the attack
			unsigned char c[CRYPTO_CIPHERTEXTBYTES];
			memset(c, 0, CRYPTO_CIPHERTEXTBYTES * sizeof(unsigned char));
			polyvec_compress(c, &pb);
			
			int h;
			// Parameter h will tell the coefficient recovered from the
			// secret key
			for (h = 0; h < 32; ++h) {
				// Compute c2
				c[KYBER_POLYVECCOMPRESSEDBYTES] = (unsigned char) h;
				

				unsigned char mp[KYBER_INDCPA_MSGBYTES]; 
				memset(&mp, 0, KYBER_INDCPA_MSGBYTES);
				// Call Oracle_m
				oracle_m(mp, c, sk_a);
				printf("h = %d, mp first byte = %x\n", h, mp[0]);
				
				// Verify if the first bit of the message mp is 1, 
				// that is the h parameter is correct
				int first_bit = mp[0] & (1 << 7);
				printf("first bit = %d\n", first_bit);
				if (first_bit == 1) {
					printf("h = %d\n", h);
					break;
				}
			}

			// Recover the key coefficient by using the check function
			sp[i * KYBER_N + k] = check_1024(h);
			
			// TODO comment this line to let the attack run
			return;
		}
	}
}

/*
 * Key recovery attack for Kyber-768. 
 * sk_a is the actual secret key of Alice and sp is the secret key recovered =
 * by the attack.
 */
void key_recovery_kyber768_v1(unsigned char *sp, unsigned char *sk_a)
{
	// First create a 32 bytes message (256 bits) where the first bit = 1 and
 	// al the other bits = 0
	unsigned char m[32];
	memset(m, 0, 32 * sizeof(unsigned char));
	m[0] |= (1 << 7);

	// Compute the round(KYBER_Q / 16) value that will be needed in the future
	float float_value = KYBER_Q / 16.0;
	float int_value = KYBER_Q / 16; 
	float diff = float_value - int_value;
	int value = (int) int_value;
	if (diff >= 0.5) {
		value += 1;
	} 

	int vec_idx;

	// Target one of the 3 polynomials of the secret key
	for (int i = 0; i < 3; ++i) {
		// Target the kth coefficient of the polynomial
		for (int k = 0; k < 256; ++k) {
			
			// Compute Bob's public key as suggested by the attack
			polyvec pb;
			memset(&pb, 0, sizeof(polyvec));
	
			if (k == 0) {
				for (vec_idx = 0; vec_idx < KYBER_K; ++vec_idx) {
					pb.vec[vec_idx].coeffs[k] = value;
				}
			} else {
				for (vec_idx = 0; vec_idx < KYBER_K; ++vec_idx) {
					pb.vec[vec_idx].coeffs[256 - k] = 0;
					pb.vec[vec_idx].coeffs[256 - k] -= value;
				}
			}
			
			// Compute the ciphertext c = (c1 || c2) as suggested by the attack
			unsigned char c[CRYPTO_CIPHERTEXTBYTES];
			memset(c, 0, CRYPTO_CIPHERTEXTBYTES * sizeof(unsigned char));
			polyvec_compress(c, &pb);
			
			int h;
			// Parameter h will tell the coefficient recovered from the
			// secret key
			for (h = 0; h < 32; ++h) {
				// Compute c2
				c[KYBER_POLYVECCOMPRESSEDBYTES] = (unsigned char) h;
				

				unsigned char mp[KYBER_INDCPA_MSGBYTES]; 
				memset(&mp, 0, KYBER_INDCPA_MSGBYTES);
				// Call Oracle_m
				oracle_m(mp, c, sk_a);
				printf("h = %d, mp[0] = %x\n", h, mp[0]);
				
				// Verify if the first bit of the message mp is 1, 
				// that is the h parameter is correct
				int first_bit = mp[0] & (1 << 7);
				printf("first bit = %d\n", first_bit);
				if (first_bit == 1) {
					printf("h = %d\n", h);
					break;
				}
			}

			// Recover the key coefficient by using the check function
			sp[i * KYBER_N + k] = check_768(h);


			// TODO comment this line to let the attack run
			return;
		}
	}
}

/*
 * Key recovery attack for Kyber-512. 
 * sk_a is the actual secret key of Alice and sp is the secret key recovered =
 * by the attack.
 */
void key_recovery_kyber512_v1(unsigned char *sp, unsigned char *sk_a)
{
	// First create a 32 bytes message (256 bits) where the first bit = 1 and
 	// al the other bits = 0
	unsigned char m[32];
	memset(m, 0, 32 * sizeof(unsigned char));
	m[0] |= (1 << 7);

	// Compute the round(KYBER_Q / 32) value that will be needed in the future
	float float_value = KYBER_Q / 8.0;
	float int_value = KYBER_Q / 8; 
	float diff = float_value - int_value;
	int value = (int) int_value;
	if (diff >= 0.5) {
		value += 1;
	} 

	int vec_idx;

	// Target one of the 2 polynomials of the secret key
	for (int i = 0; i < 2; ++i) {
		// Target the kth coefficient of the polynomial
		for (int k = 0; k < 256; ++k) {
			
			// Compute Bob's public key as suggested by the attack
			polyvec pb;
			memset(&pb, 0, sizeof(polyvec));
	
			if (k == 0) {
				for (vec_idx = 0; vec_idx < KYBER_K; ++vec_idx) {
					pb.vec[vec_idx].coeffs[k] = value;
				}
			} else {
				for (vec_idx = 0; vec_idx < KYBER_K; ++vec_idx) {
					pb.vec[vec_idx].coeffs[256 - k] = 0;
					pb.vec[vec_idx].coeffs[256 - k] -= value;
				}
			}
			
			// Compute the ciphertext c = (c1 || c2) as suggested by the attack
			unsigned char c[CRYPTO_CIPHERTEXTBYTES];
			memset(c, 0, CRYPTO_CIPHERTEXTBYTES * sizeof(unsigned char));
			polyvec_compress(c, &pb);
			
			int h;
			// Parameter h will tell the coefficient recovered from the
			// secret key
			for (h = 0; h < 8; ++h) {
				// Compute c2
				c[KYBER_POLYVECCOMPRESSEDBYTES] = (unsigned char) h;
				

				unsigned char mp[KYBER_INDCPA_MSGBYTES]; 
				memset(&mp, 0, KYBER_INDCPA_MSGBYTES);
				// Call Oracle_m
				oracle_m(mp, c, sk_a);
				printf("h = %d, mp[0] = %x\n", h, mp[0]);
				
				// Verify if the first bit of the message mp is 1, 
				// that is the h parameter is correct
				int first_bit = mp[0] & (1 << 7);
				printf("first bit = %d\n", first_bit);
				if (first_bit == 1) {
					printf("h = %d\n", h);
					break;
				}
			}

			// Recover the key coefficient by using the check function
			sp[i * KYBER_N + k] = check_512(h, 0);
			
			// TODO comment this line to let the attack run
			return;
		}
	}
}

int main(void)
{
	unsigned char key_a[CRYPTO_BYTES], key_b[CRYPTO_BYTES];                       
 	unsigned char pk[CRYPTO_PUBLICKEYBYTES];                                      
	unsigned char sendb[CRYPTO_CIPHERTEXTBYTES];                                  
	unsigned char sk_a[CRYPTO_SECRETKEYBYTES];                                    	
	
	//Alice generates a public key
    crypto_kem_keypair(pk, sk_a);

	// For debugging purposes, print the coefficients of the KYBER_K
	// polynomials of Alice's secret key
	polyvec sk_a_polyvec;
	unpack_sk(&sk_a_polyvec, sk_a);
	for (int i = 0; i < KYBER_K; ++i) {
		for (int j = 0; j < KYBER_N; ++j) {
			printf("sk.vec[%d].coeffs[%d] = %d\n", i, j, sk_a_polyvec.vec[i].coeffs[j]);
		}
	}

    //Bob derives a secret key and creates a response
    crypto_kem_enc(sendb, key_b, pk);

    //Alice uses Bobs response to get her secret key
    crypto_kem_dec(key_a, sendb, sk_a);

    if(memcmp(key_a, key_b, CRYPTO_BYTES))
      printf("ERROR keys\n");

	// The secret key recovered after the attack
	unsigned char sp[CRYPTO_SECRETKEYBYTES];
	memset(sp, 0, CRYPTO_SECRETKEYBYTES);

	// Run the attack against the desired level of security
	int type = KYBER_K;
	if (type == 2) {
		key_recovery_kyber512_v1(sp, sk_a);
	} else if (type == 3) {
		key_recovery_kyber768_v1(sp, sk_a); 
	} else if (type == 4) {
		key_recovery_kyber1024_v1(sp, sk_a);
	} else {                                                                           
		printf("ERROR KYBER_K must be in {2,3,4}\n");                                             
	}

	// Print the secret key recovered by running the attack
	printf("\nRecovered secret key\n");
	for (int i = 0; i < CRYPTO_SECRETKEYBYTES; ++i) {
		printf("%x", sp[i]);
	}
	printf("\n");
	
	return 0;
}
