/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-websocket-client.c: This file was originally part of Cockpit.
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
#include <glib/gi18n-lib.h>

#include "soup-websocket-client.h"
#include "soup-websocket-private.h"
#include "soup-headers.h"
#include "soup-message.h"

typedef SoupWebsocketConnection SoupWebsocketClient;
typedef SoupWebsocketConnectionClass SoupWebsocketClientClass;

static void soup_websocket_client_initable_interface_init (GInitableIface *initable_interface);

G_DEFINE_TYPE_WITH_CODE (SoupWebsocketClient, soup_websocket_client, SOUP_TYPE_WEBSOCKET_CONNECTION,
			 G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
						soup_websocket_client_initable_interface_init))

static void
soup_websocket_client_init (SoupWebsocketClient *self)
{
}

static gboolean
verify_handshake (SoupMessage *msg)
{
	const char *protocol, *request_protocols, *extensions, *accept_key;
	char *expected_accept_key;

	if (msg->status_code != SOUP_STATUS_SWITCHING_PROTOCOLS)
		return FALSE;

	if (!soup_message_headers_header_equals (msg->response_headers, "Upgrade", "websocket") ||
	    !soup_message_headers_header_contains (msg->response_headers, "Connection", "upgrade"))
		return FALSE;

	protocol = soup_message_headers_get_one (msg->response_headers, "Sec-WebSocket-Protocol");
	request_protocols = soup_message_headers_get_one (msg->request_headers, "Sec-WebSocket-Protocol");
	if (request_protocols && protocol &&
	    !soup_header_contains (request_protocols, protocol))
		return FALSE;

	extensions = soup_message_headers_get_list (msg->response_headers, "Sec-WebSocket-Extensions");
	if (extensions && *extensions)
		return FALSE;

	expected_accept_key = soup_websocket_get_accept_key (soup_message_headers_get_one (msg->request_headers, "Sec-WebSocket-Key"));
	accept_key = soup_message_headers_get_one (msg->response_headers, "Sec-WebSocket-Accept");
	if (!accept_key || g_ascii_strcasecmp (accept_key, expected_accept_key)) {
		g_free (expected_accept_key);
		g_debug ("received invalid or missing Sec-WebSocket-Accept header: %s", accept_key);
		return FALSE;
	}

	g_free (expected_accept_key);
	return TRUE;
}

static gboolean
soup_websocket_client_initable_init (GInitable     *initable,
				     GCancellable  *cancellable,
				     GError       **error)
{
	SoupMessage *msg;

	msg = soup_websocket_connection_get_message (SOUP_WEBSOCKET_CONNECTION (initable));
	g_return_val_if_fail (msg != NULL, FALSE);

	if (!verify_handshake (msg)) {
		g_set_error_literal (error,
				     SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE,
				     _("Received invalid WebSocket handshake from server"));
		return FALSE;
	}

	return TRUE;
}

static void
soup_websocket_client_class_init (SoupWebsocketClientClass *klass)
{
}

static void
soup_websocket_client_initable_interface_init (GInitableIface *initable_interface)
{
	initable_interface->init = soup_websocket_client_initable_init;
}

SoupWebsocketConnection *
soup_websocket_client_new (SoupMessage  *msg,
			   GIOStream    *stream,
			   GError      **error)
{
	return g_initable_new (SOUP_TYPE_WEBSOCKET_CLIENT, NULL, error,
			       "message", msg,
			       "io-stream", stream,
			       NULL);
}


void
soup_websocket_client_prepare_handshake (SoupMessage  *msg,
					 const char   *origin,
					 char        **protocols)
{
	guint32 raw[4];
	char *key;

	soup_message_headers_replace (msg->request_headers, "Upgrade", "websocket");
	soup_message_headers_append (msg->request_headers, "Connection", "Upgrade");

	raw[0] = g_random_int ();
	raw[1] = g_random_int ();
	raw[2] = g_random_int ();
	raw[3] = g_random_int ();
	key = g_base64_encode ((const guchar *)raw, sizeof (raw));
	soup_message_headers_replace (msg->request_headers, "Sec-WebSocket-Key", key);
	g_free (key);

	soup_message_headers_replace (msg->request_headers, "Sec-WebSocket-Version", "13");

	if (origin)
		soup_message_headers_replace (msg->request_headers, "Origin", origin);

	if (protocols) {
		char *protocols_str;

		protocols_str = g_strjoinv (", ", protocols);
		soup_message_headers_replace (msg->request_headers,
					      "Sec-WebSocket-Protocol", protocols_str);
		g_free (protocols_str);
	}
}
