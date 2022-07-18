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

        /* ---------------------------------------------------------- *
         * These function calls initialize openssl for correct work.  *
         * ---------------------------------------------------------- */
        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();

        /* ---------------------------------------------------------- *
         * Create the Input/Output BIO's.                             *
         * ---------------------------------------------------------- */
        certbio = BIO_new(BIO_s_file());
        outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

        /* ---------------------------------------------------------- *
         * Load the certificate from file (PEM).                      *
         * ---------------------------------------------------------- */
        ret = BIO_read_filename(certbio, cert_filestr);
        if (!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL)))
        {
                BIO_printf(outbio, "Error loading cert into memory\n");
                exit(-1);
        }

        /* ---------------------------------------------------------- *
         * Extract the certificate's public key data.                 *
         * ---------------------------------------------------------- */
        if ((pkey = X509_get_pubkey(cert)) == NULL)
                BIO_printf(outbio, "Error getting public key from certificate");

        /* ---------------------------------------------------------- *
         * Print the public key information and the key in PEM format *
         * ---------------------------------------------------------- */
        /* display the key type and size here */
        if (!PEM_write_bio_PUBKEY(outbio, pkey))
                BIO_printf(outbio, "Error writing public key data in PEM format");

        /* ---------------------------------------------------------- *
         *                                                            *
         * ---------------------------------------------------------- */
        RSA* rsa = EVP_PKEY_get1_RSA(pkey);
        
        const BIGNUM* mod= RSA_get0_n(rsa);
        const BIGNUM* exp= RSA_get0_e(rsa);

        printf("\nMódulo Hexadecimal: \n");
        BN_print_fp(stdout, mod);
        printf("\nExponente Hexadecimal: \n");
        BN_print_fp(stdout, exp);

        
        printf("\nMódulo:\n%s ", BN_bn2dec(mod));
        printf("\nExponente:\n%s ", BN_bn2dec(exp));
               
        

        /*free*/
        EVP_PKEY_free(pkey);        
        X509_free(cert);
        BIO_free_all(certbio);
        BIO_free_all(outbio);
        return(0);
        
}

int main(void)
{
        const char cert_filestr[] = "cert.pem";
        corsair(cert_filestr);
        return(0);
}