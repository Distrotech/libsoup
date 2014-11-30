/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-websocket-server.c: This file was originally part of Cockpit.
 *
 * Copyright 2013, 2014 Red Hat, Inc.
 *
 * Cockpit is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * Cockpit is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <string.h>

#include "soup-websocket-server.h"
#include "soup-websocket-private.h"
#include "soup-headers.h"
#include "soup-uri.h"

typedef SoupWebsocketConnection SoupWebsocketServer;
typedef SoupWebsocketConnectionClass SoupWebsocketServerClass;

G_DEFINE_TYPE (SoupWebsocketServer, soup_websocket_server, SOUP_TYPE_WEBSOCKET_CONNECTION)

static void
soup_websocket_server_init (SoupWebsocketServer *self)
{
}

static void
soup_websocket_server_class_init (SoupWebsocketServerClass *klass)
{
}

SoupWebsocketConnection *
soup_websocket_server_new (SoupMessage  *msg,
			   GIOStream    *stream)
{
	return g_object_new (SOUP_TYPE_WEBSOCKET_SERVER,
			     "message", msg,
			     "io-stream", stream,
			     NULL);
}

#define RESPONSE_FORBIDDEN "<html><head><title>400 Forbidden</title></head>\r\n" \
	"<body>Received invalid WebSocket request</body></html>\r\n"

static gboolean
respond_handshake_forbidden (SoupMessage *msg)
{
	soup_message_set_status (msg, SOUP_STATUS_FORBIDDEN);
	soup_message_headers_append (msg->response_headers, "Connection", "close");
	soup_message_set_response (msg, "text/html", SOUP_MEMORY_COPY,
				   RESPONSE_FORBIDDEN, strlen (RESPONSE_FORBIDDEN));

	return FALSE;
}

#define RESPONSE_BAD "<html><head><title>400 Bad Request</title></head>\r\n" \
	"<body>Received invalid WebSocket request: %s</body></html>\r\n"

static gboolean
respond_handshake_bad (SoupMessage *msg, const char *why)
{
	char *text;

	text = g_strdup_printf (RESPONSE_BAD, why);
	soup_message_set_status (msg, SOUP_STATUS_BAD_REQUEST);
	soup_message_headers_append (msg->response_headers, "Connection", "close");
	soup_message_set_response (msg, "text/html", SOUP_MEMORY_TAKE,
				   text, strlen (text));

	return FALSE;
}

static gboolean
validate_websocket_key (const char *key)
{
	/* The key must be 16 bytes, base64 encoded, meaning 22 bytes of base64
	 * data followed by 2 bytes of padding.
	 */
	if (strlen (key) != 24 || key[21] == '=' || key[22] != '=' || key[23] != '=')
		return FALSE;
	return TRUE;
}

static const char *
choose_protocol (const char *client_protocols_str,
		 const char **server_protocols)
{
	char **client_protocols;
	int i, j;

	if (!client_protocols_str)
		return NULL;
	client_protocols = g_strsplit_set (client_protocols_str, ", ", -1);
	if (!client_protocols || !client_protocols[0]) {
		g_strfreev (client_protocols);
		return NULL;
	}

	for (i = 0; server_protocols[i] != NULL; i++) {
		for (j = 0; client_protocols[j] != NULL; j++) {
			if (g_str_equal (server_protocols[i], client_protocols[j])) {
				g_debug ("agreed on protocol: %s", server_protocols[i]);
				g_strfreev (client_protocols);
				return server_protocols[i];
			}
		}
	}

	g_debug ("Unable to find a matching protocol");
	g_strfreev (client_protocols);
	return NULL;
}

gboolean
soup_websocket_server_process_handshake (SoupMessage  *msg,
					 const char   *expected_origin,
					 char        **protocols)
{
	const char *client_protocols, *chosen_protocol = NULL;
	const char *origin, *extensions;
	char *accept_key;
	const char *key;

	if (msg->method != SOUP_METHOD_GET)
		return respond_handshake_bad (msg, "method was not GET");

	if (!soup_message_headers_header_equals (msg->request_headers, "Upgrade", "websocket") ||
	    !soup_message_headers_header_contains (msg->request_headers, "Connection", "upgrade"))
		return respond_handshake_bad (msg, "not a WebSocket request");

	if (!soup_message_headers_header_equals (msg->request_headers, "Sec-WebSocket-Version", "13"))
		return respond_handshake_bad (msg, "bad WebSocket version");

	extensions = soup_message_headers_get_list (msg->request_headers, "Sec-WebSocket-Extensions");
	if (extensions && *extensions)
		return respond_handshake_bad (msg, "unsupported extension");

	key = soup_message_headers_get_one (msg->request_headers, "Sec-WebSocket-Key");
	if (key == NULL || !validate_websocket_key (key))
		return respond_handshake_bad (msg, "bad key");

	if (expected_origin) {
		origin = soup_message_headers_get_one (msg->request_headers, "Origin");
		if (!origin)
			return respond_handshake_forbidden (msg);
		if (g_ascii_strcasecmp (origin, expected_origin) != 0)
			return respond_handshake_forbidden (msg);
	}

	client_protocols = soup_message_headers_get_one (msg->request_headers, "Sec-Websocket-Protocol");
	if (protocols && protocols[0] && client_protocols) {
		chosen_protocol = choose_protocol (client_protocols, (const char **) protocols);
		if (!chosen_protocol)
			return respond_handshake_bad (msg, "unsupported protocol");
	}

	soup_message_set_status (msg, SOUP_STATUS_SWITCHING_PROTOCOLS);
	soup_message_headers_replace (msg->response_headers, "Upgrade", "websocket");
	soup_message_headers_append (msg->response_headers, "Connection", "Upgrade");

	accept_key = soup_websocket_get_accept_key (key);
	soup_message_headers_append (msg->response_headers, "Sec-WebSocket-Accept", accept_key);
	g_free (accept_key);

	if (chosen_protocol)
		soup_message_headers_append (msg->response_headers, "Sec-WebSocket-Protocol", chosen_protocol);

	return TRUE;
}
