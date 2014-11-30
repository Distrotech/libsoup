/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * This file was originally part of Cockpit.
 *
 * Copyright (C) 2013 Red Hat, Inc.
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
 * along with Cockpit; If not, see <http://www.gnu.org/licenses/>.
 */

#include "test-utils.h"

#include <sys/socket.h>

/* Hack, to get soup_websocket_get_accept_key() */
#include "../libsoup/soup-websocket.c"

typedef struct {
	GSocket *listener;
	gushort port;

	SoupSession *session;
	SoupWebsocketConnection *client;
	SoupMessage *msg;
	GError *client_error;

	SoupServer *soup_server;
	SoupWebsocketConnection *server;

	GMutex mutex;
} Test;

#define WAIT_UNTIL(cond)					\
	G_STMT_START						\
	while (!(cond)) g_main_context_iteration (NULL, TRUE);	\
	G_STMT_END

static void
on_error_not_reached (SoupWebsocketConnection *ws,
                      GError *error,
                      gpointer user_data)
{
	/* At this point we know this will fail, but is informative */
	g_assert_no_error (error);
}

static void
on_error_copy (SoupWebsocketConnection *ws,
               GError *error,
               gpointer user_data)
{
	GError **copy = user_data;
	g_assert (*copy == NULL);
	*copy = g_error_copy (error);
}

static void
setup (Test *test,
       gconstpointer data)
{
	GSocketAddress *addr;
	GError *error = NULL;

	test->listener = g_socket_new (G_SOCKET_FAMILY_IPV4,
				       G_SOCKET_TYPE_STREAM,
				       G_SOCKET_PROTOCOL_TCP,
				       &error);
	g_assert_no_error (error);

	addr = g_inet_socket_address_new_from_string ("127.0.0.1", 0);
	g_assert_no_error (error);

	g_socket_bind (test->listener, addr, TRUE, &error);
	g_assert_no_error (error);
	g_object_unref (addr);

	addr = g_socket_get_local_address (test->listener, &error);
	g_assert_no_error (error);

	test->port = g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (addr));
	g_object_unref (addr);

	g_socket_listen (test->listener, &error);
	g_assert_no_error (error);
}

static void
teardown (Test *test,
          gconstpointer data)
{
	g_clear_object (&test->listener);
	g_clear_object (&test->client);
	g_clear_object (&test->msg);
	g_clear_object (&test->server);
	g_clear_error (&test->client_error);

	if (test->session)
		soup_test_session_abort_unref (test->session);
	if (test->soup_server)
		soup_test_server_quit_unref (test->soup_server);
}

static void
setup_soup_server (Test *test,
		   const char *origin,
		   const char **protocols,
		   SoupServerWebsocketCallback callback,
		   gpointer user_data)
{
	GError *error = NULL;

	test->soup_server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_listen_socket (test->soup_server, test->listener, 0, &error);
	g_assert_no_error (error);

	soup_server_add_websocket_handler (test->soup_server, "/unix",
					   origin, (char **) protocols,
					   callback, user_data, NULL);
}

static void
client_connect (Test *test,
		const char *origin,
		const char **protocols,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	char *url;

	if (!test->session)
		test->session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);

	url = g_strdup_printf ("ws://127.0.0.1:%u/unix", test->port);
	test->msg = soup_message_new ("GET", url);
	g_free (url);

	soup_session_websocket_connect_async (test->session, test->msg,
					      origin, (char **) protocols,
					      NULL, callback, user_data);
}

static void
on_text_message (SoupWebsocketConnection *ws,
                 SoupWebsocketDataType type,
                 GBytes *message,
                 gpointer user_data)
{
	GBytes **receive = user_data;
	g_assert_cmpint (type, ==, SOUP_WEBSOCKET_DATA_TEXT);
	g_assert (*receive == NULL);
	g_assert (message != NULL);
	*receive = g_bytes_ref (message);
}

static void
on_close_set_flag (SoupWebsocketConnection *ws,
                   gpointer user_data)
{
	gboolean *flag = user_data;
	g_assert (*flag == FALSE);
	*flag = TRUE;
}


static void
got_server_connection (SoupServer              *server,
		       SoupWebsocketConnection *connection,
		       const char              *path,
		       SoupClientContext       *client,
		       gpointer                 user_data)
{
	Test *test = user_data;

	test->server = g_object_ref (connection);
}

static void
got_client_connection (GObject *object,
		       GAsyncResult *result,
		       gpointer user_data)
{
	Test *test = user_data;

	test->client = soup_session_websocket_connect_finish (SOUP_SESSION (object),
							      result, &test->client_error);
}

static void
setup_simple (Test *test)
{
	setup_soup_server (test, NULL, NULL, got_server_connection, test);
	client_connect (test, NULL, NULL, got_client_connection, test);
	WAIT_UNTIL (test->server != NULL);
	WAIT_UNTIL (test->client != NULL || test->client_error != NULL);
	g_assert_no_error (test->client_error);
}

static void
test_handshake (Test *test,
                gconstpointer data)
{
	setup_simple (test);

	g_assert_cmpint (soup_websocket_connection_get_state (test->client), ==, SOUP_WEBSOCKET_STATE_OPEN);
	g_assert_cmpint (soup_websocket_connection_get_state (test->server), ==, SOUP_WEBSOCKET_STATE_OPEN);
}

#define TEST_STRING "this is a test"

static void
test_send_client_to_server (Test *test,
                            gconstpointer data)
{
	GBytes *received = NULL;
	const char *contents;
	gsize len;

	setup_simple (test);

	g_signal_connect (test->server, "message", G_CALLBACK (on_text_message), &received);

	soup_websocket_connection_send (test->client, SOUP_WEBSOCKET_DATA_TEXT,
					TEST_STRING, -1);

	WAIT_UNTIL (received != NULL);

	/* Received messages should be null terminated (outside of len) */
	contents = g_bytes_get_data (received, &len);
	g_assert_cmpstr (contents, ==, TEST_STRING);
	g_assert_cmpint (len, ==, strlen (TEST_STRING));

	g_bytes_unref (received);
}

static void
test_send_server_to_client (Test *test,
                            gconstpointer data)
{
	GBytes *received = NULL;
	const char *contents;
	gsize len;

	setup_simple (test);

	g_signal_connect (test->client, "message", G_CALLBACK (on_text_message), &received);

	soup_websocket_connection_send (test->server, SOUP_WEBSOCKET_DATA_TEXT,
					TEST_STRING, -1);

	WAIT_UNTIL (received != NULL);

	/* Received messages should be null terminated (outside of len) */
	contents = g_bytes_get_data (received, &len);
	g_assert_cmpstr (contents, ==, TEST_STRING);
	g_assert_cmpint (len, ==, strlen (TEST_STRING));

	g_bytes_unref (received);
}

static void
test_send_big_packets (Test *test,
                       gconstpointer data)
{
	GBytes *sent = NULL;
	GBytes *received = NULL;

	setup_simple (test);

	g_signal_connect (test->client, "message", G_CALLBACK (on_text_message), &received);

	sent = g_bytes_new_take (g_strnfill (400, '!'), 400);
	soup_websocket_connection_send (test->server, SOUP_WEBSOCKET_DATA_TEXT,
					g_bytes_get_data (sent, NULL),
					g_bytes_get_size (sent));
	WAIT_UNTIL (received != NULL);
	g_assert (g_bytes_equal (sent, received));
	g_bytes_unref (sent);
	g_bytes_unref (received);
	received = NULL;

	sent = g_bytes_new_take (g_strnfill (100 * 1000, '?'), 100 * 1000);
	soup_websocket_connection_send (test->server, SOUP_WEBSOCKET_DATA_TEXT,
					g_bytes_get_data (sent, NULL),
					g_bytes_get_size (sent));
	WAIT_UNTIL (received != NULL);
	g_assert (g_bytes_equal (sent, received));
	g_bytes_unref (sent);
	g_bytes_unref (received);
}

static void
test_send_bad_data (Test *test,
                    gconstpointer unused)
{
	GError *error = NULL;
	GIOStream *io;
	gsize written;
	const char *frame;

	setup_simple (test);

	g_signal_handlers_disconnect_by_func (test->server, on_error_not_reached, NULL);
	g_signal_connect (test->server, "error", G_CALLBACK (on_error_copy), &error);

	io = soup_websocket_connection_get_io_stream (test->client);

	/* Bad UTF-8 frame */
	frame = "\x81\x04\xEE\xEE\xEE\xEE";
	if (!g_output_stream_write_all (g_io_stream_get_output_stream (io),
					frame, 6, &written, NULL, NULL))
		g_assert_not_reached ();
	g_assert_cmpuint (written, ==, 6);

	WAIT_UNTIL (error != NULL);
	g_assert_error (error, SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_CLOSE_BAD_DATA);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);

	g_assert_cmpuint (soup_websocket_connection_get_close_code (test->client), ==, SOUP_WEBSOCKET_CLOSE_BAD_DATA);

	g_error_free (error);
}

static void
test_protocol_negotiate (Test *test,
                         gconstpointer unused)
{
	const char *server_protocols[] = { "aaa", "bbb", "ccc", NULL };
	const char *client_protocols[] = { "bbb", "ccc", NULL };

	setup_soup_server (test, NULL, server_protocols, got_server_connection, test);
	client_connect (test, NULL, client_protocols, got_client_connection, test);
	WAIT_UNTIL (test->server != NULL);
	WAIT_UNTIL (test->client != NULL || test->client_error != NULL);
	g_assert_no_error (test->client_error);

	g_assert_cmpstr (soup_websocket_connection_get_protocol (test->client), ==, "bbb");
	g_assert_cmpstr (soup_websocket_connection_get_protocol (test->server), ==, "bbb");
}

static void
test_protocol_mismatch (Test *test,
                        gconstpointer unused)
{
	const char *server_protocols[] = { "aaa", "bbb", "ccc", NULL };
	const char *client_protocols[] = { "ddd", NULL };

	setup_soup_server (test, NULL, server_protocols, got_server_connection, test);
	client_connect (test, NULL, client_protocols, got_client_connection, test);
	WAIT_UNTIL (test->client_error != NULL);

	g_assert_error (test->client_error, SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_ERROR_NOT_WEBSOCKET);
}

static void
test_protocol_server_any (Test *test,
                          gconstpointer unused)
{
	const char *client_protocols[] = { "aaa", "bbb", "ccc", NULL };

	setup_soup_server (test, NULL, NULL, got_server_connection, test);
	client_connect (test, NULL, client_protocols, got_client_connection, test);
	WAIT_UNTIL (test->server != NULL);
	WAIT_UNTIL (test->client != NULL || test->client_error != NULL);
	g_assert_no_error (test->client_error);

	g_assert_cmpstr (soup_websocket_connection_get_protocol (test->client), ==, NULL);
	g_assert_cmpstr (soup_websocket_connection_get_protocol (test->server), ==, NULL);
	g_assert_cmpstr (soup_message_headers_get_one (test->msg->response_headers, "Sec-WebSocket-Protocol"), ==, NULL);
}

static void
test_protocol_client_any (Test *test,
                          gconstpointer unused)
{
	const char *server_protocols[] = { "aaa", "bbb", "ccc", NULL };

	setup_soup_server (test, NULL, server_protocols, got_server_connection, test);
	client_connect (test, NULL, NULL, got_client_connection, test);
	WAIT_UNTIL (test->server != NULL);
	WAIT_UNTIL (test->client != NULL || test->client_error != NULL);
	g_assert_no_error (test->client_error);

	g_assert_cmpstr (soup_websocket_connection_get_protocol (test->client), ==, NULL);
	g_assert_cmpstr (soup_websocket_connection_get_protocol (test->server), ==, NULL);
	g_assert_cmpstr (soup_message_headers_get_one (test->msg->response_headers, "Sec-WebSocket-Protocol"), ==, NULL);
}

static void
test_close_clean_client (Test *test,
                         gconstpointer data)
{
	gboolean close_event_client = FALSE;
	gboolean close_event_server = FALSE;

	setup_simple (test);

	g_signal_connect (test->client, "close", G_CALLBACK (on_close_set_flag), &close_event_client);
	g_signal_connect (test->server, "close", G_CALLBACK (on_close_set_flag), &close_event_server);

	soup_websocket_connection_close (test->client, SOUP_WEBSOCKET_CLOSE_GOING_AWAY, "give me a reason");
	g_assert_cmpint (soup_websocket_connection_get_state (test->client), ==, SOUP_WEBSOCKET_STATE_CLOSING);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->server) == SOUP_WEBSOCKET_STATE_CLOSED);
	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);

	g_assert (close_event_client);
	g_assert (close_event_server);

	g_assert_cmpint (soup_websocket_connection_get_close_code (test->client), ==, SOUP_WEBSOCKET_CLOSE_GOING_AWAY);
	g_assert_cmpint (soup_websocket_connection_get_close_code (test->server), ==, SOUP_WEBSOCKET_CLOSE_GOING_AWAY);
	g_assert_cmpstr (soup_websocket_connection_get_close_data (test->server), ==, "give me a reason");
}

static void
test_close_clean_server (Test *test,
                         gconstpointer data)
{
	gboolean close_event_client = FALSE;
	gboolean close_event_server = FALSE;

	setup_simple (test);

	g_signal_connect (test->client, "close", G_CALLBACK (on_close_set_flag), &close_event_client);
	g_signal_connect (test->server, "close", G_CALLBACK (on_close_set_flag), &close_event_server);

	soup_websocket_connection_close (test->server, SOUP_WEBSOCKET_CLOSE_GOING_AWAY, "another reason");
	g_assert_cmpint (soup_websocket_connection_get_state (test->server), ==, SOUP_WEBSOCKET_STATE_CLOSING);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->server) == SOUP_WEBSOCKET_STATE_CLOSED);
	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);

	g_assert (close_event_client);
	g_assert (close_event_server);

	g_assert_cmpint (soup_websocket_connection_get_close_code (test->server), ==, SOUP_WEBSOCKET_CLOSE_GOING_AWAY);
	g_assert_cmpint (soup_websocket_connection_get_close_code (test->client), ==, SOUP_WEBSOCKET_CLOSE_GOING_AWAY);
	g_assert_cmpstr (soup_websocket_connection_get_close_data (test->client), ==, "another reason");
}

static gboolean
on_closing_send_message (SoupWebsocketConnection *ws,
                         gpointer data)
{
	GBytes *message = data;

	soup_websocket_connection_send (ws, SOUP_WEBSOCKET_DATA_TEXT,
					g_bytes_get_data (message, NULL),
					g_bytes_get_size (message));
	g_signal_handlers_disconnect_by_func (ws, on_closing_send_message, data);
	return TRUE;
}

static void
test_message_after_closing (Test *test,
                            gconstpointer data)
{
	gboolean close_event_client = FALSE;
	gboolean close_event_server = FALSE;
	GBytes *received = NULL;
	GBytes *message;

	setup_simple (test);

	message = g_bytes_new ("another test because", 20);
	g_signal_connect (test->client, "close", G_CALLBACK (on_close_set_flag), &close_event_client);
	g_signal_connect (test->client, "message", G_CALLBACK (on_text_message), &received);
	g_signal_connect (test->server, "close", G_CALLBACK (on_close_set_flag), &close_event_server);
	g_signal_connect (test->server, "closing", G_CALLBACK (on_closing_send_message), message);

	soup_websocket_connection_close (test->client, SOUP_WEBSOCKET_CLOSE_GOING_AWAY, "another reason");
	g_assert_cmpint (soup_websocket_connection_get_state (test->client), ==, SOUP_WEBSOCKET_STATE_CLOSING);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->server) == SOUP_WEBSOCKET_STATE_CLOSED);
	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);

	g_assert (close_event_client);
	g_assert (close_event_server);

	g_assert (received != NULL);
	g_assert (g_bytes_equal (message, received));

	g_bytes_unref (received);
	g_bytes_unref (message);
}

static GIOStream *
mock_accept (GSocket *listener)
{
	GSocket *sock;
	GSocketConnection *conn;
	GError *error = NULL;

	sock = g_socket_accept (listener, NULL, &error);
	g_assert_no_error (error);

	conn = g_socket_connection_factory_create_connection (sock);
	g_assert (conn != NULL);
	g_object_unref (sock);

	return G_IO_STREAM (conn);
}

static void
mock_perform_handshake (GIOStream *io)
{
	SoupMessageHeaders *headers;
	char buffer[1024], *headers_end;
	gssize count;
	const char *key;
	char *accept;
	gsize written;

	/* Assumes client codes sends headers as a single write() */
	count = g_input_stream_read (g_io_stream_get_input_stream (io),
				     buffer, sizeof (buffer), NULL, NULL);
	g_assert (count > 0);

	/* Parse the incoming request */
	headers_end = g_strstr_len (buffer, sizeof (buffer), "\n\r\n");
	g_assert (headers_end != NULL);
	headers_end += 3;

	headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_REQUEST);
	g_assert (soup_headers_parse_request (buffer, headers_end - buffer, headers, NULL, NULL, NULL));
	g_assert_cmpuint (headers_end - buffer, <, sizeof (buffer));

	key = soup_message_headers_get_one (headers, "Sec-WebSocket-Key");
	accept = soup_websocket_get_accept_key (key);

	count = g_snprintf (buffer, sizeof (buffer),
			    "HTTP/1.1 101 Switching Protocols\r\n"
			    "Upgrade: websocket\r\n"
			    "Connection: Upgrade\r\n"
			    "Sec-WebSocket-Accept: %s\r\n"
			    "\r\n", accept);
	g_free (accept);

	if (!g_output_stream_write_all (g_io_stream_get_output_stream (io),
					buffer, count, &written, NULL, NULL))
		g_assert_not_reached ();
	g_assert_cmpuint (count, ==, written);

	soup_message_headers_free (headers);
}

static gpointer
handshake_then_timeout_server_thread (gpointer user_data)
{
	Test *test = user_data;
	GIOStream *io;

	io = mock_accept (test->listener);
	mock_perform_handshake (io);

	/* don't close until the client has timed out */
	g_mutex_lock (&test->mutex);
	g_mutex_unlock (&test->mutex);

	g_object_unref (io);
	return NULL;
}

static void
test_close_after_timeout (Test *test,
			  gconstpointer data)
{
	gboolean close_event = FALSE;
	GThread *thread;

	g_mutex_lock (&test->mutex);

	/* Note that no server is around in this test, so no close happens */
	thread = g_thread_new ("timeout-thread", handshake_then_timeout_server_thread, test);

	client_connect (test, NULL, NULL, got_client_connection, test);
	WAIT_UNTIL (test->client != NULL || test->client_error != NULL);
	g_assert_no_error (test->client_error);

	g_signal_connect (test->client, "close", G_CALLBACK (on_close_set_flag), &close_event);
	g_signal_connect (test->client, "error", G_CALLBACK (on_error_not_reached), NULL);
	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_OPEN);

	/* Now try and close things */
	soup_websocket_connection_close (test->client, 0, NULL);
	g_assert_cmpint (soup_websocket_connection_get_state (test->client), ==, SOUP_WEBSOCKET_STATE_CLOSING);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);

	g_assert (close_event == TRUE);

	/* Now actually close the server side stream */
	g_mutex_unlock (&test->mutex);
	g_thread_join (thread);
}

static gpointer
send_fragments_server_thread (gpointer user_data)
{
	Test *test = user_data;
	GIOStream *io;
	gsize written;

	const char fragments[] = "\x01\x04""one "   /* !fin | opcode */
		"\x00\x04""two "   /* !fin | no opcode */
		"\x80\x05""three"; /* fin  | no opcode */

	io = mock_accept (test->listener);
	mock_perform_handshake (io);

	/* synchronize... */
	g_mutex_lock (&test->mutex);
	g_mutex_unlock (&test->mutex);

	if (!g_output_stream_write_all (g_io_stream_get_output_stream (io),
					fragments, sizeof (fragments) -1, &written, NULL, NULL))
		g_assert_not_reached ();
	g_assert_cmpuint (written, ==, sizeof (fragments) - 1);
	g_object_unref (io);

	return NULL;
}

static void
test_receive_fragmented (Test *test,
			 gconstpointer data)
{
	GThread *thread;
	GBytes *received = NULL;
	GBytes *expect;

	g_mutex_lock (&test->mutex);

	/* Note that no server is around in this test, so no close happens */
	thread = g_thread_new ("fragment-thread", send_fragments_server_thread, test);

	client_connect (test, NULL, NULL, got_client_connection, test);
	WAIT_UNTIL (test->client != NULL || test->client_error != NULL);
	g_assert_no_error (test->client_error);

	g_mutex_unlock (&test->mutex);

	g_signal_connect (test->client, "error", G_CALLBACK (on_error_not_reached), NULL);
	g_signal_connect (test->client, "message", G_CALLBACK (on_text_message), &received);

	WAIT_UNTIL (received != NULL);
	expect = g_bytes_new ("one two three", 13);
	g_assert (g_bytes_equal (expect, received));
	g_bytes_unref (expect);
	g_bytes_unref (received);

	g_thread_join (thread);
}

int
main (int argc,
      char *argv[])
{
	int ret;

	test_init (argc, argv, NULL);

	g_test_add ("/websocket/handshake", Test, NULL, setup,
		    test_handshake, teardown);
	g_test_add ("/websocket/send-client-to-server", Test, NULL, setup,
		    test_send_client_to_server, teardown);
	g_test_add ("/websocket/send-server-to-client", Test, NULL, setup,
		    test_send_server_to_client, teardown);
	g_test_add ("/websocket/send-big-packets", Test, NULL, setup,
		    test_send_big_packets, teardown);
	g_test_add ("/websocket/send-bad-data", Test, NULL, setup,
		    test_send_bad_data, teardown);
	g_test_add ("/websocket/protocol-negotiate", Test, NULL, setup,
		    test_protocol_negotiate, teardown);
	g_test_add ("/websocket/protocol-mismatch", Test, NULL, setup,
		    test_protocol_mismatch, teardown);
	g_test_add ("/websocket/protocol-server-any", Test, NULL, setup,
		    test_protocol_server_any, teardown);
	g_test_add ("/websocket/protocol-client-any", Test, NULL, setup,
		    test_protocol_client_any, teardown);
	g_test_add ("/websocket/close-clean-client", Test, NULL, setup,
		    test_close_clean_client, teardown);
	g_test_add ("/websocket/close-clean-server", Test, NULL, setup,
		    test_close_clean_server, teardown);
	g_test_add ("/websocket/receive-fragmented", Test, NULL, setup,
		    test_receive_fragmented, teardown);
	g_test_add ("/websocket/message-after-closing", Test, NULL, setup,
		    test_message_after_closing, teardown);

	if (g_test_slow ()) {
		g_test_add ("/websocket/close-after-timeout", Test, NULL, setup,
			    test_close_after_timeout, teardown);
	}

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
