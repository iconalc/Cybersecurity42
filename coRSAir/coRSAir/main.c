/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: icondado <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/07/20 13:31:30 by icondado          #+#    #+#             */
/*   Updated: 2022/07/20 13:44:19 by icondado         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "corsair.h"

int main(int argc, char **argv)
{
	if (argc == 2)
	{
		printf("Fichero con certificado: \n%s\n", argv[1]);
		corsair(argv[1]);
	}else if(argc == 3)
	{
		printf("Números primos: \n%s %s\n", argv[1], argv[2]);
		create_pkey(argv[1], argv[2]);
	}else
	{
		printf("Faltan datos o datos incorrectos.");
	}
	return(0);
}
