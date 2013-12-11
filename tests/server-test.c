/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2007-2012 Red Hat, Inc.
 */

#include "test-utils.h"

SoupServer *server;
SoupURI *base_uri, *ssl_base_uri;

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	soup_message_headers_append (msg->response_headers,
				     "X-Handled-By", "server_callback");

	if (!strcmp (path, "*")) {
		debug_printf (1, "    default server_callback got request for '*'!\n");
		errors++;
		soup_message_set_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR);
		return;
	}

	if (msg->method != SOUP_METHOD_GET && msg->method != SOUP_METHOD_POST) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);
	soup_message_set_response (msg, "text/plain",
				   SOUP_MEMORY_STATIC, "index", 5);
}

static void
server_star_callback (SoupServer *server, SoupMessage *msg,
		      const char *path, GHashTable *query,
		      SoupClientContext *context, gpointer data)
{
	soup_message_headers_append (msg->response_headers,
				     "X-Handled-By", "star_callback");

	if (strcmp (path, "*") != 0) {
		debug_printf (1, "    server_star_callback got request for '%s'!\n", path);
		errors++;
		soup_message_set_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR);
		return;
	}

	if (msg->method != SOUP_METHOD_OPTIONS) {
		soup_message_set_status (msg, SOUP_STATUS_METHOD_NOT_ALLOWED);
		return;
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);
}

/* Server handlers for "*" work but are separate from handlers for
 * all other URIs. #590751
 */
static void
do_star_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	SoupURI *star_uri;
	const char *handled_by;

	debug_printf (1, "\nOPTIONS *\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	star_uri = soup_uri_copy (base_uri);
	soup_uri_set_path (star_uri, "*");

	debug_printf (1, "  Testing with no handler\n");
	msg = soup_message_new_from_uri ("OPTIONS", star_uri);
	soup_session_send_message (session, msg);

	if (msg->status_code != SOUP_STATUS_NOT_FOUND) {
		debug_printf (1, "    Unexpected response: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	handled_by = soup_message_headers_get_one (msg->response_headers,
						   "X-Handled-By");
	if (handled_by) {
		/* Should have been rejected by SoupServer directly */
		debug_printf (1, "    Message reached handler '%s'\n",
			      handled_by);
		errors++;
	}
	g_object_unref (msg);

	soup_server_add_handler (server, "*", server_star_callback, NULL, NULL);

	debug_printf (1, "  Testing with handler\n");
	msg = soup_message_new_from_uri ("OPTIONS", star_uri);
	soup_session_send_message (session, msg);

	if (msg->status_code != SOUP_STATUS_OK) {
		debug_printf (1, "    Unexpected response: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	handled_by = soup_message_headers_get_one (msg->response_headers,
						   "X-Handled-By");
	if (!handled_by) {
		debug_printf (1, "    Message did not reach handler!\n");
		errors++;
	} else if (strcmp (handled_by, "star_callback") != 0) {
		debug_printf (1, "    Message reached incorrect handler '%s'\n",
			      handled_by);
		errors++;
	}
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
	soup_uri_free (star_uri);
}

static void
do_one_server_aliases_test (SoupURI    *uri,
			    const char *alias,
			    gboolean    succeed)
{
	GSocketClient *client;
	GSocketConnectable *addr;
	GSocketConnection *conn;
	GInputStream *in;
	GOutputStream *out;
	GError *error = NULL;
	GString *req;
	static char buf[1024];

	debug_printf (1, "  %s via %s\n", alias, uri->scheme);

	/* There's no way to make libsoup's client side send an absolute
	 * URI (to a non-proxy server), so we have to fake this.
	 */

	client = g_socket_client_new ();
	if (uri->scheme == SOUP_URI_SCHEME_HTTPS) {
		g_socket_client_set_tls (client, TRUE);
		g_socket_client_set_tls_validation_flags (client, 0);
	}
	addr = g_network_address_new (uri->host, uri->port);

	conn = g_socket_client_connect (client, addr, NULL, &error);
	g_object_unref (addr);
	g_object_unref (client);
	if (!conn) {
		debug_printf (1, "    error connecting to server: %s\n",
			      error->message);
		g_error_free (error);
		errors++;
		return;
	}

	in = g_io_stream_get_input_stream (G_IO_STREAM (conn));
	out = g_io_stream_get_output_stream (G_IO_STREAM (conn));

	req = g_string_new (NULL);
	g_string_append_printf (req, "GET %s://%s:%d HTTP/1.1\r\n",
				alias, uri->host, uri->port);
	g_string_append_printf (req, "Host: %s:%d\r\n",
				uri->host, uri->port);
	g_string_append (req, "Connection: close\r\n\r\n");

	if (!g_output_stream_write_all (out, req->str, req->len, NULL, NULL, &error)) {
		debug_printf (1, "    error sending request: %s\n",
			      error->message);
		g_error_free (error);
		errors++;
		g_object_unref (conn);
		g_string_free (req, TRUE);
		return;
	}
	g_string_free (req, TRUE);

	if (!g_input_stream_read_all (in, buf, sizeof (buf), NULL, NULL, &error)) {
		debug_printf (1, "    error reading response: %s\n",
			      error->message);
		g_error_free (error);
		errors++;
		g_object_unref (conn);
		return;
	}

	if ((succeed && !g_str_has_prefix (buf, "HTTP/1.1 200 ")) ||
	    (!succeed && !g_str_has_prefix (buf, "HTTP/1.1 400 "))) {
		debug_printf (1, "    unexpected response: %.*s\n",
			      (int) strcspn (buf, "\r\n"), buf);
		errors++;
	}

	g_io_stream_close (G_IO_STREAM (conn), NULL, NULL);
	g_object_unref (conn);
}

static void
do_server_aliases_test (void)
{
	char *http_good[] = { "http", "dav", NULL };
	char *http_bad[] = { "https", "davs", "fred", NULL };
	char *https_good[] = { "https", "davs", NULL };
	char *https_bad[] = { "http", "dav", "fred", NULL };
	int i;

	debug_printf (1, "\nserver aliases test\n");

	for (i = 0; http_good[i]; i++)
		do_one_server_aliases_test (base_uri, http_good[i], TRUE);
	for (i = 0; http_bad[i]; i++)
		do_one_server_aliases_test (base_uri, http_bad[i], FALSE);

	if (tls_available) {
		for (i = 0; https_good[i]; i++)
			do_one_server_aliases_test (ssl_base_uri, https_good[i], TRUE);
		for (i = 0; https_bad[i]; i++)
			do_one_server_aliases_test (ssl_base_uri, https_bad[i], FALSE);
	}
}

static void
do_dot_dot_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	SoupURI *uri;

	debug_printf (1, "\n'..' smuggling test\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);

	uri = soup_uri_new_with_base (base_uri, "/..%2ftest");
	msg = soup_message_new_from_uri ("GET", uri);
	soup_uri_free (uri);

	soup_session_send_message (session, msg);

	if (msg->status_code != SOUP_STATUS_BAD_REQUEST) {
		debug_printf (1, "      FAILED: %d %s (expected Bad Request)\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
}

static void
ipv6_server_callback (SoupServer *server, SoupMessage *msg,
		      const char *path, GHashTable *query,
		      SoupClientContext *context, gpointer data)
{
	const char *host;
	GSocketAddress *addr;
	char expected_host[128];

	host = soup_message_headers_get_one (msg->request_headers, "Host");
	if (!host) {
		debug_printf (1, "    request has no Host header!\n");
		errors++;
		soup_message_set_status (msg, SOUP_STATUS_BAD_REQUEST);
		return;
	}

	addr = soup_client_context_get_local_address (context);
	g_snprintf (expected_host, sizeof (expected_host),
		    "[::1]:%d",
		    g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (addr)));

	if (strcmp (host, expected_host) == 0)
		soup_message_set_status (msg, SOUP_STATUS_OK);
	else {
		debug_printf (1, "    request has incorrect Host header '%s'\n", host);
		errors++;
		soup_message_set_status (msg, SOUP_STATUS_BAD_REQUEST);
	}
}

static void
do_ipv6_test (void)
{
	SoupServer *ipv6_server;
	SoupURI *ipv6_uri;
	SoupSession *session;
	SoupMessage *msg;

	// FIXME: deal with lack of IPv6 support

	debug_printf (1, "\nIPv6 server test\n");

	ipv6_server = soup_test_server_new (SOUP_TEST_SERVER_DEFAULT);
	soup_server_add_handler (ipv6_server, NULL, ipv6_server_callback, NULL, NULL);
	ipv6_uri = soup_test_server_get_uri (server, "http", "::1");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);

	debug_printf (1, "  HTTP/1.1\n");
	msg = soup_message_new_from_uri ("GET", ipv6_uri);
	soup_session_send_message (session, msg);
	if (!SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		debug_printf (1, "    request failed: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	g_object_unref (msg);

	debug_printf (1, "  HTTP/1.0\n");
	msg = soup_message_new_from_uri ("GET", ipv6_uri);
	soup_message_set_http_version (msg, SOUP_HTTP_1_0);
	soup_session_send_message (session, msg);
	if (!SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		debug_printf (1, "    request failed: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	g_object_unref (msg);

	soup_uri_free (ipv6_uri);
	soup_test_session_abort_unref (session);
	soup_test_server_quit_unref (ipv6_server);
}

int
main (int argc, char **argv)
{
	char *http_aliases[] = { "dav", NULL };
	char *https_aliases[] = { "davs", NULL };

	test_init (argc, argv, NULL);

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_test_server_get_uri (server, "http", NULL);

	g_object_set (G_OBJECT (server),
		      SOUP_SERVER_HTTP_ALIASES, http_aliases,
		      NULL);

	if (tls_available) {
		ssl_base_uri = soup_test_server_get_uri (server, "https", NULL);
		g_object_set (G_OBJECT (server),
			      SOUP_SERVER_HTTPS_ALIASES, https_aliases,
			      NULL);
	}

	do_star_test ();
	do_server_aliases_test ();
	do_dot_dot_test ();
	do_ipv6_test ();

	soup_uri_free (base_uri);
	soup_test_server_quit_unref (server);

	if (tls_available)
		soup_uri_free (ssl_base_uri);

	test_cleanup ();
	return errors != 0;
}
