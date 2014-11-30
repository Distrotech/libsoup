/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-websocket.c: This file was originally part of Cockpit.
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

#include <stdlib.h>
#include <string.h>

#include "soup-websocket.h"
#include "soup-websocket-private.h"

/**
 * SoupWebsocketState:
 * @SOUP_WEBSOCKET_STATE_CONNECTING: the WebSocket is not yet ready to send messages
 * @SOUP_WEBSOCKET_STATE_OPEN: the Websocket is ready to send messages
 * @SOUP_WEBSOCKET_STATE_CLOSING: the Websocket is in the process of closing down, no further messages sent
 * @SOUP_WEBSOCKET_STATE_CLOSED: the Websocket is completely closed down
 *
 * The WebSocket is in the %SOUP_WEBSOCKET_STATE_CONNECTING state during initial
 * connection setup, and handshaking. If the handshake or connection fails it
 * can go directly to the %SOUP_WEBSOCKET_STATE_CLOSED state from here.
 *
 * Once the WebSocket handshake completes successfully it will be in the
 * %SOUP_WEBSOCKET_STATE_OPEN state. During this state, and only during this state
 * can WebSocket messages be sent.
 *
 * WebSocket messages can be received during either the %SOUP_WEBSOCKET_STATE_OPEN
 * or %SOUP_WEBSOCKET_STATE_CLOSING states.
 *
 * The WebSocket goes into the %SOUP_WEBSOCKET_STATE_CLOSING state once it has
 * successfully sent a close request to the peer. If we had not yet received
 * an earlier close request from the peer, then the WebSocket waits for a
 * response to the close request (until a timeout).
 *
 * Once actually closed completely down the WebSocket state is
 * %SOUP_WEBSOCKET_STATE_CLOSED. No communication is possible during this state.
 *
 * Since: 2.50
 */

GQuark
soup_websocket_error_get_quark (void)
{
	return g_quark_from_static_string ("web-socket-error-quark");
}

char *
soup_websocket_get_accept_key (const char *key)
{
	gsize digest_len = 20;
	guchar digest[digest_len];
	GChecksum *checksum;

	g_return_val_if_fail (key != NULL, NULL);

	checksum = g_checksum_new (G_CHECKSUM_SHA1);
	g_return_val_if_fail (checksum != NULL, NULL);

	g_checksum_update (checksum, (guchar *)key, -1);

	/* magic from: http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17 */
	g_checksum_update (checksum, (guchar *)"258EAFA5-E914-47DA-95CA-C5AB0DC85B11", -1);

	g_checksum_get_digest (checksum, digest, &digest_len);
	g_checksum_free (checksum);

	g_assert (digest_len == 20);

	return g_base64_encode (digest, digest_len);
}
