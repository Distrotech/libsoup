/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-websocket-server.h: This file was originally part of Cockpit.
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

#ifndef __SOUP_WEBSOCKET_SERVER_H__
#define __SOUP_WEBSOCKET_SERVER_H__

#include <gio/gio.h>

#include <libsoup/soup-websocket-connection.h>
#include <libsoup/soup-message-headers.h>

G_BEGIN_DECLS

#define SOUP_TYPE_WEBSOCKET_SERVER         (soup_websocket_server_get_type ())
#define SOUP_WEBSOCKET_SERVER(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), SOUP_TYPE_WEBSOCKET_SERVER, SoupWebsocketServer))
#define SOUP_IS_WEBSOCKET_SERVER(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), SOUP_TYPE_WEBSOCKET_SERVER))
#define SOUP_WEBSOCKET_SERVER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), SOUP_TYPE_WEBSOCKET_SERVER, SoupWebsocketServerClass))
#define SOUP_IS_WEBSOCKET_SERVER_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), SOUP_TYPE_WEBSOCKET_SERVER))

GType soup_websocket_server_get_type (void) G_GNUC_CONST;

gboolean soup_websocket_server_process_handshake (SoupMessage  *msg,
						  const char   *expected_origin,
						  char        **protocols);

SoupWebsocketConnection *soup_websocket_server_new (SoupMessage  *msg,
						    GIOStream    *stream);

G_END_DECLS

#endif /* __SOUP_WEBSOCKET_SERVER_H__ */
