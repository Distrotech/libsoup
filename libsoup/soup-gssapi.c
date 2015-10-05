/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-gssapi.c: GSSAPI related functions
 *
 * Copyright (C) 2013 Guido Guenther <agx@sigxcpu.org>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <soup-status.h>
#include <soup-gssapi.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

int
soup_gss_client_init (SoupNegotiateConnectionState *conn, const char *host, GError **err);

int
soup_gss_client_step (SoupNegotiateConnectionState *conn, const char *host, GError **err);

void
soup_gss_client_cleanup (SoupNegotiateConnectionState *conn);

static void
soup_gss_error (OM_uint32 err_maj, OM_uint32 err_min, GError **err)
{
	OM_uint32 maj_stat, min_stat, msg_ctx = 0;
	gss_buffer_desc status;
	char *buf_maj = NULL, *buf_min = NULL;

	do {
		maj_stat = gss_display_status (&min_stat,
					       err_maj,
					       GSS_C_GSS_CODE,
					       GSS_C_NO_OID,
					       &msg_ctx,
					       &status);
		if (GSS_ERROR (maj_stat))
			break;

		buf_maj = g_strdup ((char *) status.value);
		gss_release_buffer (&min_stat, &status);

		maj_stat = gss_display_status (&min_stat,
					       err_min,
					       GSS_C_MECH_CODE,
					       GSS_C_NULL_OID,
					       &msg_ctx,
					       &status);
		if (!GSS_ERROR (maj_stat)) {
			buf_min = g_strdup ((char *) status.value);
			gss_release_buffer (&min_stat, &status);
		}

		if (err && *err == NULL) {
			g_set_error (err,
				     SOUP_HTTP_ERROR,
				     SOUP_STATUS_GSSAPI_FAILED,
				     "%s %s",
				     buf_maj,
				     buf_min ? buf_min : "");
		}
		g_free (buf_maj);
		g_free (buf_min);
		buf_min = buf_maj = NULL;
	} while (!GSS_ERROR (maj_stat) && msg_ctx != 0);
}

G_MODULE_EXPORT int
soup_gss_client_init (SoupNegotiateConnectionState *conn, const char *host, GError **err)
{
	OM_uint32 maj_stat, min_stat;
	char *service = NULL;
	gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
	gboolean ret = FALSE;
	gchar *h;

	conn->server_name = GSS_C_NO_NAME;
	conn->context = GSS_C_NO_CONTEXT;

	h = g_ascii_strdown (host, -1);
	service = g_strconcat ("HTTP/", h, NULL);
	token.length = strlen (service);
	token.value = (char *) service;

	maj_stat = gss_import_name (&min_stat,
				    &token,
				    (gss_OID) GSS_KRB5_NT_PRINCIPAL_NAME,
				    &conn->server_name);

	if (GSS_ERROR (maj_stat)) {
		soup_gss_error (maj_stat, min_stat, err);
		ret = FALSE;
		goto out;
	}

	ret = TRUE;
out:
	g_free (h);
	g_free (service);
	return ret;
}

G_MODULE_EXPORT int
soup_gss_client_step (SoupNegotiateConnectionState *conn, const char *challenge, GError **err)
{
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc in = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
	int ret = AUTH_GSS_CONTINUE;

	g_clear_pointer (&conn->response_header, g_free);

	if (challenge && *challenge) {
		size_t len;
		in.value = g_base64_decode (challenge, &len);
		in.length = len;
	}

	maj_stat = gss_init_sec_context (&min_stat,
					 GSS_C_NO_CREDENTIAL,
					 &conn->context,
					 conn->server_name,
					 GSS_C_NO_OID,
					 GSS_C_MUTUAL_FLAG,
					 GSS_C_INDEFINITE,
					 GSS_C_NO_CHANNEL_BINDINGS,
					 &in,
					 NULL,
					 &out,
					 NULL,
					 NULL);

	if ((maj_stat != GSS_S_COMPLETE) && (maj_stat != GSS_S_CONTINUE_NEEDED)) {
		soup_gss_error (maj_stat, min_stat, err);
		ret = AUTH_GSS_ERROR;
		goto out;
	}

	ret = (maj_stat == GSS_S_COMPLETE) ? AUTH_GSS_COMPLETE : AUTH_GSS_CONTINUE;
	if (out.length) {
		char *response = g_base64_encode ((const unsigned char *) out.value, out.length);
		conn->response_header = g_strconcat ("Negotiate ", response, NULL);
		g_free (response);
		maj_stat = gss_release_buffer (&min_stat, &out);
	}

out:
	if (out.value)
		gss_release_buffer (&min_stat, &out);
	if (in.value)
		g_free (in.value);
	return ret;
}


G_MODULE_EXPORT void
soup_gss_client_cleanup (SoupNegotiateConnectionState *conn)
{
	OM_uint32 min_stat;

	gss_release_name (&min_stat, &conn->server_name);
}
