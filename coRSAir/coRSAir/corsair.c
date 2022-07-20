/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   corsair.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: icondado <icondado@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/07/15 12:57:01 by icondado          #+#    #+#             */
/*   Updated: 2022/07/20 16:20:48 by icondado         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "corsair.h"

char *corsair(const char *cert_filestr)
{     
	 printf("\nFunción que calcula de un certificado su clave pública.\n");
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
	{
		BIO_printf(outbio, "Error getting public key from certificate");
		exit(-1);
	}
    // Print the public key information and the key in PEM format
    // display the key type and size here
    if(!PEM_write_bio_PUBKEY(outbio, pkey))
	{
		BIO_printf(outbio, "Error writing public key data in PEM format");
		exit(-1);
	}
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

char	*create_pkey(char *prime1, char *prime2)
{
	printf("\nFunción que calcula de dos números primos una clave privada.\n");
	printf("\nPrimos función: \n%s %s", prime1, prime2);
	//Variables
	BN_CTX *ctx = BN_CTX_new(); //valor temporal
	RSA	*rsa = RSA_new(); //Extructura
	BIGNUM	*p = BN_new(); //Primo 1
	BIGNUM	*q = BN_new(); //Primo 2
	BIGNUM	*e = BN_new();
	BIGNUM	*n;
	BIGNUM	*m;
	BIGNUM	*a;
	BIGNUM	*b;
	BIGNUM	*d;	
	BIGNUM	*dmp1;	
	BIGNUM 	*dmq1;	
	BIGNUM	*iqmp;
	BIGNUM	*uno = BN_new();
	BIGNUM	*temp_p;
	BIGNUM	*temp_q;
	BIO	*outbio;
	int	ret;

	//Para calcular el exponente privado de una clave rsa la formula sería
	//d = e mod_inv m , donde m = n - (p + q -1)
	BN_dec2bn(&e, "65537");
	BN_dec2bn(&uno, "1");
	BN_dec2bn(&p, prime1);
	BN_dec2bn(&q, prime2);

	BN_CTX_start(ctx);
	n = BN_CTX_get(ctx);
	m = BN_CTX_get(ctx);
	a = BN_CTX_get(ctx);
	b = BN_CTX_get(ctx);
	d = BN_CTX_get(ctx);
	temp_p = BN_CTX_get(ctx);
	temp_q = BN_CTX_get(ctx);
	dmp1 = BN_CTX_get(ctx);
	dmq1 = BN_CTX_get(ctx);
	iqmp = BN_CTX_get(ctx);

	BN_mul(n, p, q, ctx);
	BN_add(a, p, q);
	BN_sub(b, a, uno);
	BN_sub(m, n, b);
	BN_mod_inverse(d, e, m, ctx);
	BN_sub(temp_p, p, uno);
	BN_sub(temp_q, q, uno);
	BN_mod(dmp1, d, temp_p, ctx);
	BN_mod(dmq1, d, temp_q, ctx);
	BN_mod_inverse(iqmp, q, p, ctx);

	RSA_set0_key(rsa, n, e, d);
	RSA_set0_factors(rsa, p, q);
	RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);

	//print public and private key
	outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
	RSA_print(outbio, rsa, 0); //Detalles de la clave privada
	printf("\n");
	ret = PEM_write_bio_RSAPublicKey(outbio, rsa);
	if(ret != 1)
	{
		BIO_printf(outbio, "Error writing public key datainPEM format");
		return(0);
	}
	printf("\n\n");
	ret = PEM_write_bio_RSAPrivateKey(outbio, rsa, NULL, NULL, 0, NULL, NULL);
	if(ret != 1)
	{
		BIO_printf(outbio, "Error writing private key datainPEM format");
		return(0);
	}

	BIO_free_all(outbio);
	RSA_free(rsa);
	return(0);
}
