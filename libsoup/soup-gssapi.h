/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-auth-negotiate.c: HTTP Negotiate Authentication helper
 *
 * Copyright (C) 2013 Guido Guenther <agx@sigxcpu.org>
 */

#ifndef SOUP_GSSAPI_H
#define SOUP_GSSAPI_H

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifdef HAVE_GSSAPI
# include <gssapi/gssapi.h>
#endif

#define AUTH_GSS_ERROR      -1
#define AUTH_GSS_COMPLETE    1
#define AUTH_GSS_CONTINUE    0

typedef enum {
	SOUP_NEGOTIATE_NEW,
	SOUP_NEGOTIATE_RECEIVED_CHALLENGE, /* received intial negotiate header */
	SOUP_NEGOTIATE_SENT_RESPONSE,      /* sent response to server */
	SOUP_NEGOTIATE_FAILED
} SoupNegotiateState;

typedef struct {
	SoupNegotiateState state;

#ifdef HAVE_GSSAPI
	gss_ctx_id_t context;
	gss_name_t   server_name;
#endif

	char *response_header;
} SoupNegotiateConnectionState;

#endif /* SOUP_GSSAPI_H */
