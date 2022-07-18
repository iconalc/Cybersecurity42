/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   corsair.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: icondado <icondado@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/07/14 16:22:54 by icondado          #+#    #+#             */
/*   Updated: 2022/07/18 18:19:22 by icondado         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef CORSAIR_H
# define CORSAIR_H

# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/pem.h>
# include <openssl/x509.h>
# include <openssl/rsa.h>
# include <stdio.h>
# include <unistd.h>

char *corsair(const char *cert_filestr);

#endif
