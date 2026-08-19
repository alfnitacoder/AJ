/*	$OpenBSD: sshbuf-getput-crypto.c,v 1.12 2024/08/15 00:51:51 djm Exp $	*/
/*
 * Copyright (c) 2011 Damien Miller
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define SSHBUF_INTERNAL
#include "ajos_sshbuf_config.h"
#include "openssh/includes.h"
#include "openssh/ssherr.h"
#include "openssh/sshbuf.h"

// OpenSSL not available in kernel - stub out OpenSSL functions
#ifndef WITH_OPENSSL
#define WITH_OPENSSL 0
#endif

// Stub out OpenSSL types and functions
#if !WITH_OPENSSL
typedef void BIGNUM;
typedef void EC_POINT;
typedef void EC_GROUP;
typedef void EC_KEY;
typedef void EVP_PKEY;
#define POINT_CONVERSION_UNCOMPRESSED 4

// Stub out OpenSSL-dependent functions - not available in kernel
int
sshbuf_get_bignum2(struct sshbuf *buf, BIGNUM **valp)
{
	// Stub - OpenSSL not available
	(void)buf;
	(void)valp;
	return SSH_ERR_INVALID_ARGUMENT;
}

int
sshbuf_get_ec(struct sshbuf *buf, EC_POINT *v, const EC_GROUP *g)
{
	(void)buf; (void)v; (void)g;
	return SSH_ERR_INVALID_ARGUMENT;
}

int
sshbuf_get_eckey(struct sshbuf *buf, EC_KEY *v)
{
	(void)buf; (void)v;
	return SSH_ERR_INVALID_ARGUMENT;
}

int
sshbuf_put_bignum2(struct sshbuf *buf, const BIGNUM *v)
{
	(void)buf; (void)v;
	return SSH_ERR_INVALID_ARGUMENT;
}

int
sshbuf_put_ec(struct sshbuf *buf, const EC_POINT *v, const EC_GROUP *g)
{
	(void)buf; (void)v; (void)g;
	return SSH_ERR_INVALID_ARGUMENT;
}

int
sshbuf_put_eckey(struct sshbuf *buf, const EC_KEY *v)
{
	(void)buf; (void)v;
	return SSH_ERR_INVALID_ARGUMENT;
}

int
sshbuf_put_ec_pkey(struct sshbuf *buf, EVP_PKEY *pkey)
{
	(void)buf; (void)pkey;
	return SSH_ERR_INVALID_ARGUMENT;
}
#endif
