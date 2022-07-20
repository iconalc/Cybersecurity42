/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   corsair.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: icondado <icondado@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/07/15 12:57:01 by icondado          #+#    #+#             */
/*   Updated: 2022/07/18 18:18:41 by icondado         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "corsair.h"

char *corsair(const char *cert_filestr)
{
       
        EVP_PKEY *pkey = NULL;
        BIO *certbio = NULL;
        BIO *outbio = NULL;
        X509 *cert = NULL;
        int ret;

        // These function calls initialize openssl for correct work.
        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();

        // Create the Input/Output BIO's.
        certbio = BIO_new(BIO_s_file());
        outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

        // Load the certificate from file (PEM)
        ret = BIO_read_filename(certbio, cert_filestr);
        if(!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL)))
        {
                BIO_printf(outbio, "Error loading cert into memory\n");
                exit(-1);
        }

        // Extract the certificate's public key data
        if((pkey = X509_get_pubkey(cert)) == NULL)
                BIO_printf(outbio, "Error getting public key from certificate");

        // Print the public key information and the key in PEM format
        // display the key type and size here
        if(!PEM_write_bio_PUBKEY(outbio, pkey))
                BIO_printf(outbio, "Error writing public key data in PEM format");

        // Extract the modulus and exponent from the public key
	RSA* rsa = EVP_PKEY_get1_RSA(pkey);
        
        const BIGNUM* mod= RSA_get0_n(rsa); //módulo
        const BIGNUM* exp= RSA_get0_e(rsa); //exponente

        // Hexadecimal
	printf("\nMódulo Hexadecimal: \n");
        BN_print_fp(stdout, mod);
        printf("\nExponente Hexadecimal: \n");
        BN_print_fp(stdout, exp);

        // Decimal
        printf("\nMódulo Decimal: \n%s",BN_bn2dec(mod));
        printf("\nExponente Decimal: \n%s\n", BN_bn2dec(exp));

        // Free
        EVP_PKEY_free(pkey);        
        X509_free(cert);
        BIO_free_all(certbio);
        BIO_free_all(outbio);
        
	return(0);
        
}

void	create_pkey(char *prime1, char *prime2)
{
BN_CTX *ctx = BN_CTX_new(); //valor temporal
RSA	*rsa = RSA_new(); //Extructura
BIGNUM	*p = BN_new(); //Primo 1
BIGNUM	*q = BN_new(); //Primo 2
BIGNUM	*e = BN_new();
BIGNUM	*n;
BIGNUM	*d;	//Módulo inverso (exponente privado)
BIGNUM	*dmp1;	//Valores para
BIGNUM 	*dmq1;	//desencriptar la clave
BIGNUM	*iqmp;
BIGNUM	*uno = BN_new();
BIGNUM	*temp_p;
BIGNUM	*temp_q;
BIO	*outbio;
int	ret;

BN_dec2bn(&e, "65537");
BN_dec2bn(&uno, "1");
BN_dec2bn(&p, prime1);
BN_dec2bn(&q, prime2);

BN_CTX_start(ctx);

n = BN_CTX_get(ctx);
BN_mul(n, p, q, ctx);

d = BN_CTX_get(ctx);
BN_mod_inverse(d, e, n, ctx);

temp_p = BN_CTX_get(ctx);
BN_sub(temp_p, p, uno);

temp_q = BN_CTX_get(ctx);
BN_sub(temp_q, q, uno);

dmp1 = BN_CTX_get(ctx);
BN_mod(dmp1, d, temp_p, ctx);

dmq1 = BN_CTX_get(ctx);
BN_mod(dmq1, d, temp_p, ctx);

iqmp = BN_CTX_get(ctx);
BN_mod_inverse(iqmp, q, p, ctx);

RSA_set0_key(rsa, n, e, d);
RSA_set0_factors(rsa, p, q);
RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);

//print public and private key
outbio = BIO_new_fd((int)stdout, BIO_NOCLOSE);
RSA_print(outbio, rsa, 0); //Detalles de la clave privada
printf("\n");
ret = PEM_write_bio_RSAPublicKey(outbio, rsa);
if(ret != 1)
{
	BIO_printf(outbio, "Error writing public key datainPEM format");
	return;
}
printf("\n\n");
ret = PEM_write_bio_RSAPrivatekey(outbio, rsa, NULL, NULL, 0, NULL, NULL);
if(ret != 1)
{
	BIO_printf(outbio, "Error writing private key datainPEM format");
	return;
}
BIO_free_all(outbio);
RSA_free(rsa);
}

int main(int argc, char **argv)
{
	if( argc == 2)
	{
		printf("Fichero con certificado: \n%s\n", argv[1]);
        	const char *cert_filestr= argv[1];
        	corsair(cert_filestr);
	}else if(argc == 4)
	{
		printf("Parte 2.");
		char *prime1= argv[2];
		char *prime2= argv[3];
		create_pkey(prime1, prime2);
	}else
	{
		printf("Faltan parámetros.\n");
	}
	return(0);
}
