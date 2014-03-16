/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message-client-io.c: client-side request/response
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include <glib/gi18n-lib.h>

#include "soup.h"
#include "soup-connection.h"
#include "soup-message-private.h"
#include "soup-message-queue.h"
#include "soup-misc-private.h"

static guint
parse_response_headers (SoupMessage *msg,
			SoupHTTPInputStream *http,
			gpointer user_data,
			GError **error)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupHTTPVersion version;

	g_free (msg->reason_phrase);
	msg->reason_phrase = NULL;
	if (!soup_http_input_stream_parse_response_headers (http,
							    msg->method,
							    &version,
							    &msg->status_code,
							    &msg->reason_phrase,
							    msg->response_headers,
							    error))
		return SOUP_STATUS_MALFORMED;

	g_object_notify (G_OBJECT (msg), SOUP_MESSAGE_STATUS_CODE);
	g_object_notify (G_OBJECT (msg), SOUP_MESSAGE_REASON_PHRASE);

	if (version < priv->http_version) {
		priv->http_version = version;
		g_object_notify (G_OBJECT (msg), SOUP_MESSAGE_HTTP_VERSION);
	}

	return SOUP_STATUS_OK;
}

static void
get_request_headers (SoupMessage *msg, GString *header,
		     SoupEncoding *encoding, gpointer user_data)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageQueueItem *item = user_data;
	SoupURI *uri = soup_message_get_uri (msg);
	char *uri_host;
	char *uri_string;
	SoupMessageHeadersIter iter;
	const char *name, *value;

	if (strchr (uri->host, ':'))
		uri_host = g_strdup_printf ("[%.*s]", (int) strcspn (uri->host, "%"), uri->host);
	else if (g_hostname_is_non_ascii (uri->host))
		uri_host = g_hostname_to_ascii (uri->host);
	else
		uri_host = uri->host;

	if (msg->method == SOUP_METHOD_CONNECT) {
		/* CONNECT URI is hostname:port for tunnel destination */
		uri_string = g_strdup_printf ("%s:%d", uri_host, uri->port);
	} else {
		gboolean proxy = soup_connection_is_via_proxy (item->conn);

		/* Proxy expects full URI to destination. Otherwise
		 * just the path.
		 */
		uri_string = soup_uri_to_string (uri, !proxy);

		if (proxy && uri->fragment) {
			/* Strip fragment */
			char *fragment = strchr (uri_string, '#');
			if (fragment)
				*fragment = '\0';
		}
	}

	g_string_append_printf (header, "%s %s HTTP/1.%d\r\n",
				msg->method, uri_string,
				(priv->http_version == SOUP_HTTP_1_0) ? 0 : 1);

	if (!soup_message_headers_get_one (msg->request_headers, "Host")) {
		if (soup_uri_uses_default_port (uri)) {
			g_string_append_printf (header, "Host: %s\r\n",
						uri_host);
		} else {
			g_string_append_printf (header, "Host: %s:%d\r\n",
						uri_host, uri->port);
		}
	}
	g_free (uri_string);
	if (uri_host != uri->host)
		g_free (uri_host);

	*encoding = soup_message_headers_get_encoding (msg->request_headers);
	if ((*encoding == SOUP_ENCODING_CONTENT_LENGTH ||
	     *encoding == SOUP_ENCODING_NONE) &&
	    (msg->request_body->length > 0 ||
	     soup_message_headers_get_one (msg->request_headers, "Content-Type")) &&
	    !soup_message_headers_get_content_length (msg->request_headers)) {
		*encoding = SOUP_ENCODING_CONTENT_LENGTH;
		soup_message_headers_set_content_length (msg->request_headers,
							 msg->request_body->length);
	}

	soup_message_headers_iter_init (&iter, msg->request_headers);
	while (soup_message_headers_iter_next (&iter, &name, &value))
		g_string_append_printf (header, "%s: %s\r\n", name, value);
	g_string_append (header, "\r\n");
}

void
soup_message_send_request (SoupMessageQueueItem      *item,
			   SoupMessageCompletionFn    completion_cb,
			   gpointer                   user_data)
{
	GMainContext *async_context;
	GIOStream *iostream;

	if (!SOUP_IS_SESSION_SYNC (item->session)) {
		async_context = soup_session_get_async_context (item->session);
		if (!async_context)
			async_context = g_main_context_default ();
	} else
		async_context = NULL;
	iostream = soup_socket_get_iostream (soup_connection_get_socket (item->conn));

	soup_message_io_client (item, iostream, async_context,
				get_request_headers,
				parse_response_headers,
				item,
				completion_cb, user_data);
}
