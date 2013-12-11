/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#include "test-utils.h"

SoupURI *base_uri;
char *server2_uri;
SoupSession *async_session, *sync_session;

typedef struct {
	const char *method;
	const char *path;
	guint status_code;
	gboolean repeat;
} TestRequest;

typedef struct {
	TestRequest requests[3];
	guint final_status;
	guint request_api_final_status;
} TestCase;

static TestCase tests[] = {
	/* A redirecty response to a GET or HEAD should cause a redirect */

	{ { { "GET", "/301", 301 },
	    { "GET", "/", 200 },
	    { NULL } }, 200 },
	{ { { "GET", "/302", 302 },
	    { "GET", "/", 200 },
	    { NULL } }, 200 },
	{ { { "GET", "/303", 303 },
	    { "GET", "/", 200 },
	    { NULL } }, 200 },
	{ { { "GET", "/307", 307 },
	    { "GET", "/", 200 },
	    { NULL } }, 200 },
	{ { { "HEAD", "/301", 301 },
	    { "HEAD", "/", 200 },
	    { NULL } }, 200 },
	{ { { "HEAD", "/302", 302 },
	    { "HEAD", "/", 200 },
	    { NULL } }, 200 },
	/* 303 is a nonsensical response to HEAD, but some sites do
	 * it anyway. :-/
	 */
	{ { { "HEAD", "/303", 303 },
	    { "HEAD", "/", 200 },
	    { NULL } }, 200 },
	{ { { "HEAD", "/307", 307 },
	    { "HEAD", "/", 200 },
	    { NULL } }, 200 },

	/* A non-redirecty response to a GET or HEAD should not */

	{ { { "GET", "/300", 300 },
	    { NULL } }, 300 },
	{ { { "GET", "/304", 304 },
	    { NULL } }, 304 },
	{ { { "GET", "/305", 305 },
	    { NULL } }, 305 },
	{ { { "GET", "/306", 306 },
	    { NULL } }, 306 },
	{ { { "GET", "/308", 308 },
	    { NULL } }, 308 },
	{ { { "HEAD", "/300", 300 },
	    { NULL } }, 300 },
	{ { { "HEAD", "/304", 304 },
	    { NULL } }, 304 },
	{ { { "HEAD", "/305", 305 },
	    { NULL } }, 305 },
	{ { { "HEAD", "/306", 306 },
	    { NULL } }, 306 },
	{ { { "HEAD", "/308", 308 },
	    { NULL } }, 308 },
	
	/* Test double-redirect */

	{ { { "GET", "/301/302", 301 },
	    { "GET", "/302", 302 },
	    { "GET", "/", 200 } }, 200 },
	{ { { "HEAD", "/301/302", 301 },
	    { "HEAD", "/302", 302 },
	    { "HEAD", "/", 200 } }, 200 },

	/* POST should only automatically redirect on 301, 302 and 303 */

	{ { { "POST", "/301", 301 },
	    { "GET", "/", 200 },
	    { NULL } }, 200 },
	{ { { "POST", "/302", 302 },
	    { "GET", "/", 200 },
	    { NULL } }, 200 },
	{ { { "POST", "/303", 303 },
	    { "GET", "/", 200 },
	    { NULL } }, 200 },
	{ { { "POST", "/307", 307 },
	    { NULL } }, 307 },

	/* Test behavior with recoverably-bad Location header */
	{ { { "GET", "/bad", 302 },
	    { "GET", "/bad%20with%20spaces", 200 },
	    { NULL } }, 200 },

	/* Test behavior with irrecoverably-bad Location header */
	{ { { "GET", "/bad-no-host", 302 },
	    { NULL } }, SOUP_STATUS_MALFORMED, 302 },

	/* Test infinite redirection */
	{ { { "GET", "/bad-recursive", 302, TRUE },
	    { NULL } }, SOUP_STATUS_TOO_MANY_REDIRECTS },

	/* Test redirection to a different server */
	{ { { "GET", "/server2", 302 },
	    { "GET", "/on-server2", 200 },
	    { NULL } }, 200 },
};
static const int n_tests = G_N_ELEMENTS (tests);

static void
got_headers (SoupMessage *msg, gpointer user_data)
{
	TestRequest **treq = user_data;
	const char *location;

	debug_printf (2, "    -> %d %s\n", msg->status_code,
		      msg->reason_phrase);
	location = soup_message_headers_get_one (msg->response_headers,
						 "Location");
	if (location)
		debug_printf (2, "       Location: %s\n", location);

	if (!(*treq)->method)
		return;

	soup_test_assert_message_status (msg, (*treq)->status_code);
}

static void
restarted (SoupMessage *msg, gpointer user_data)
{
	TestRequest **treq = user_data;
	SoupURI *uri = soup_message_get_uri (msg);

	debug_printf (2, "    %s %s\n", msg->method, uri->path);

	if ((*treq)->method && !(*treq)->repeat)
		(*treq)++;

	soup_test_assert ((*treq)->method,
			  "Expected to be done");

	g_assert_cmpstr (msg->method, ==, (*treq)->method);
	g_assert_cmpstr (uri->path, ==, (*treq)->path);
}

static void
do_message_api_test (SoupSession *session, TestCase *test)
{
	SoupURI *uri;
	SoupMessage *msg;
	TestRequest *treq;

	debug_printf (1, "%s %s\n",
		      test->requests[0].method,
		      test->requests[0].path);

	uri = soup_uri_new_with_base (base_uri, test->requests[0].path);
	msg = soup_message_new_from_uri (test->requests[0].method, uri);
	soup_uri_free (uri);

	if (msg->method == SOUP_METHOD_POST) {
		soup_message_set_request (msg, "text/plain",
					  SOUP_MEMORY_STATIC,
					  "post body",
					  strlen ("post body"));
	}

	treq = &test->requests[0];
	g_signal_connect (msg, "got_headers",
			  G_CALLBACK (got_headers), &treq);
	g_signal_connect (msg, "restarted",
			  G_CALLBACK (restarted), &treq);

	soup_session_send_message (session, msg);

	soup_test_assert_message_status (msg, test->final_status);

	g_object_unref (msg);
	debug_printf (2, "\n");
}

static void
do_request_api_test (SoupSession *session, TestCase *test)
{
	SoupURI *uri;
	SoupRequestHTTP *reqh;
	SoupMessage *msg;
	TestRequest *treq;
	GInputStream *stream;
	GError *error = NULL;
	guint final_status;

	debug_printf (1, "%s %s\n",
		      test->requests[0].method,
		      test->requests[0].path);

	final_status = test->request_api_final_status;
	if (!final_status)
		final_status = test->final_status;

	uri = soup_uri_new_with_base (base_uri, test->requests[0].path);
	reqh = soup_session_request_http_uri (session,
					      test->requests[0].method,
					      uri, &error);
	soup_uri_free (uri);
	g_assert_no_error (error);
	if (error) {
		g_error_free (error);
		debug_printf (2, "\n");
		return;
	}

	msg = soup_request_http_get_message (reqh);
	if (msg->method == SOUP_METHOD_POST) {
		soup_message_set_request (msg, "text/plain",
					  SOUP_MEMORY_STATIC,
					  "post body",
					  strlen ("post body"));
	}

	treq = &test->requests[0];
	g_signal_connect (msg, "got_headers",
			  G_CALLBACK (got_headers), &treq);
	g_signal_connect (msg, "restarted",
			  G_CALLBACK (restarted), &treq);

	stream = soup_test_request_send (SOUP_REQUEST (reqh), NULL, 0, &error);

	if (SOUP_STATUS_IS_TRANSPORT_ERROR (final_status)) {
		g_assert_error (error, SOUP_HTTP_ERROR, final_status);
		g_clear_error (&error);

		g_assert_null (stream);
		g_clear_object (&stream);

		g_object_unref (msg);
		g_object_unref (reqh);
		debug_printf (2, "\n");
		return;
	}

	g_assert_no_error (error);
	if (error) {
		g_error_free (error);
		g_object_unref (msg);
		g_object_unref (reqh);
		debug_printf (2, "\n");
		return;
	}

	soup_test_request_read_all (SOUP_REQUEST (reqh), stream, NULL, &error);
	g_assert_no_error (error);
	g_clear_error (&error);

	soup_test_request_close_stream (SOUP_REQUEST (reqh), stream, NULL, &error);
	g_assert_no_error (error);
	g_clear_error (&error);
	g_object_unref (stream);

	g_assert_cmpint (msg->status_code, ==, final_status);

	g_object_unref (msg);
	g_object_unref (reqh);
	debug_printf (2, "\n");
}

static void
do_async_msg_api_test (gconstpointer test)
{
	do_message_api_test (async_session, (TestCase *)test);
}

static void
do_async_req_api_test (gconstpointer test)
{
	do_request_api_test (async_session, (TestCase *)test);
}

static void
do_sync_msg_api_test (gconstpointer test)
{
	do_message_api_test (sync_session, (TestCase *)test);
}

static void
do_sync_req_api_test (gconstpointer test)
{
	do_request_api_test (sync_session, (TestCase *)test);
}

typedef struct {
	SoupSession *session;
	SoupMessage *msg1, *msg2;
	SoupURI *uri1, *uri2;
	SoupSocket *sock1, *sock2;
} ConnectionTestData;

static void
msg2_finished (SoupSession *session, SoupMessage *msg2, gpointer user_data)
{
	soup_test_assert_message_status (msg2, SOUP_STATUS_OK);
}

static void
unpause_msg1 (SoupMessage *msg2, gpointer user_data)
{
       ConnectionTestData *data = user_data;

       soup_test_assert (data->sock1 != NULL,
			 "msg1 has no connection");
       soup_test_assert (data->sock2 != NULL,
			 "msg2 has no connection");
       soup_test_assert (data->sock1 != data->sock2,
			 "Both messages sharing the same connection");

       soup_session_unpause_message (data->session, data->msg1);
}

static gboolean
msg1_just_restarted (gpointer user_data)
{
	ConnectionTestData *data = user_data;

	soup_session_pause_message (data->session, data->msg1);

	data->msg2 = soup_message_new_from_uri ("GET", data->uri2);

	g_signal_connect (data->msg2, "got_body",
			  G_CALLBACK (unpause_msg1), data);

	soup_session_queue_message (data->session, data->msg2, msg2_finished, data);
	return FALSE;
}

static void
msg1_about_to_restart (SoupMessage *msg1, gpointer user_data)
{
	ConnectionTestData *data = user_data;

	/* Do nothing when loading the redirected-to resource */
	if (!SOUP_STATUS_IS_REDIRECTION (data->msg1->status_code))
		return;

	/* We have to pause msg1 after the I/O finishes, but before
	 * the queue runs again.
	 */
	g_idle_add_full (G_PRIORITY_HIGH, msg1_just_restarted, data, NULL);
}

static void
request_started (SoupSession *session, SoupMessage *msg,
		 SoupSocket *socket, gpointer user_data)
{
	ConnectionTestData *data = user_data;

	if (msg == data->msg1)
		data->sock1 = socket;
	else if (msg == data->msg2)
		data->sock2 = socket;
	else
		g_warn_if_reached ();
}

static void
do_connection_test (void)
{
	ConnectionTestData data;

	memset (&data, 0, sizeof (data));

	data.session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	g_signal_connect (data.session, "request-started",
			  G_CALLBACK (request_started), &data);

	data.uri1 = soup_uri_new_with_base (base_uri, "/301");
	data.uri2 = soup_uri_new_with_base (base_uri, "/");
	data.msg1 = soup_message_new_from_uri ("GET", data.uri1);

	g_signal_connect (data.msg1, "got-body",
			  G_CALLBACK (msg1_about_to_restart), &data);
	soup_session_send_message (data.session, data.msg1);

	soup_test_assert_message_status (data.msg1, SOUP_STATUS_OK);

	g_object_unref (data.msg1);
	soup_uri_free (data.uri1);
	soup_uri_free (data.uri2);

	soup_test_session_abort_unref (data.session);
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	char *remainder;
	guint status_code;

	/* Make sure that a HTTP/1.0 redirect doesn't cause an
	 * HTTP/1.0 re-request. (#521848)
	 */
	if (soup_message_get_http_version (msg) == SOUP_HTTP_1_0) {
		soup_message_set_status (msg, SOUP_STATUS_BAD_REQUEST);
		return;
	}

	if (g_str_has_prefix (path, "/bad")) {
		if (!strcmp (path, "/bad")) {
			soup_message_set_status (msg, SOUP_STATUS_FOUND);
			soup_message_headers_replace (msg->response_headers,
						      "Location",
						      "/bad with spaces");
		} else if (!strcmp (path, "/bad-recursive")) {
			soup_message_set_status (msg, SOUP_STATUS_FOUND);
			soup_message_headers_replace (msg->response_headers,
						      "Location",
						      "/bad-recursive");
		} else if (!strcmp (path, "/bad-no-host")) {
			soup_message_set_status (msg, SOUP_STATUS_FOUND);
			soup_message_headers_replace (msg->response_headers,
						      "Location",
						      "about:blank");
		} else if (!strcmp (path, "/bad with spaces"))
			soup_message_set_status (msg, SOUP_STATUS_OK);
		else
			soup_message_set_status (msg, SOUP_STATUS_NOT_FOUND);
		return;
	} else if (!strcmp (path, "/server2")) {
		soup_message_set_status (msg, SOUP_STATUS_FOUND);
		soup_message_headers_replace (msg->response_headers,
					      "Location",
					      server2_uri);
		return;
	} else if (!strcmp (path, "/")) {
		if (msg->method != SOUP_METHOD_GET &&
		    msg->method != SOUP_METHOD_HEAD) {
			soup_message_set_status (msg, SOUP_STATUS_METHOD_NOT_ALLOWED);
			return;
		}

		/* Make sure that redirecting a POST clears the body */
		if (msg->request_body->length) {
			soup_message_set_status (msg, SOUP_STATUS_BAD_REQUEST);
			return;
		}

		soup_message_set_status (msg, SOUP_STATUS_OK);

		/* FIXME: this is wrong, though it doesn't matter for
		 * the purposes of this test, and to do the right
		 * thing currently we'd have to set Content-Length by
		 * hand.
		 */
		if (msg->method != SOUP_METHOD_HEAD) {
			soup_message_set_response (msg, "text/plain",
						   SOUP_MEMORY_STATIC,
						   "OK\r\n", 4);
		}
		return;
	}

	status_code = strtoul (path + 1, &remainder, 10);
	if (!SOUP_STATUS_IS_REDIRECTION (status_code) ||
	    (*remainder && *remainder != '/')) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_FOUND);
		return;
	}

	/* See above comment re bug 521848. We only test this on the
	 * double-redirects so that we get connection-reuse testing
	 * the rest of the time.
	 */
	if (*remainder == '/')
		soup_message_set_http_version (msg, SOUP_HTTP_1_0);

	soup_message_set_redirect (msg, status_code,
				   *remainder ? remainder : "/");
}

static void
server2_callback (SoupServer *server, SoupMessage *msg,
		  const char *path, GHashTable *query,
		  SoupClientContext *context, gpointer data)
{
	soup_message_set_status (msg, SOUP_STATUS_OK);
}

int
main (int argc, char **argv)
{
	GMainLoop *loop;
	SoupServer *server, *server2;
	guint port;
	char *path;
	int n, ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL,
				 server_callback, NULL, NULL);
	port = soup_server_get_port (server);
	base_uri = soup_uri_new ("http://127.0.0.1");
	soup_uri_set_port (base_uri, port);

	server2 = soup_test_server_new (TRUE);
	soup_server_add_handler (server2, NULL,
				 server2_callback, NULL, NULL);
	server2_uri = g_strdup_printf ("http://127.0.0.1:%d/on-server2",
				       soup_server_get_port (server2));

	loop = g_main_loop_new (NULL, TRUE);

	async_session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					       SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					       NULL);
	sync_session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);

	for (n = 0; n < n_tests; n++) {
		path = g_strdup_printf ("/redirect/async/msg/%d-%s-%d", n
					, tests[n].requests[0].method,
					tests[n].requests[0].status_code);
		g_test_add_data_func (path, &tests[n], do_async_msg_api_test);
		g_free (path);

		path = g_strdup_printf ("/redirect/async/req/%d-%s-%d", n,
					tests[n].requests[0].method,
					tests[n].requests[0].status_code);
		g_test_add_data_func (path, &tests[n], do_async_req_api_test);
		g_free (path);

		path = g_strdup_printf ("/redirect/sync/msg/%d-%s-%d", n,
					tests[n].requests[0].method,
					tests[n].requests[0].status_code);
		g_test_add_data_func (path, &tests[n], do_sync_msg_api_test);
		g_free (path);

		path = g_strdup_printf ("/redirect/sync/req/%d-%s-%d", n,
					tests[n].requests[0].method,
					tests[n].requests[0].status_code);
		g_test_add_data_func (path, &tests[n], do_sync_req_api_test);
		g_free (path);
	}

	g_test_add_func ("/redirect/reuse", do_connection_test);

	ret = g_test_run ();

	g_main_loop_unref (loop);
	soup_uri_free (base_uri);
	soup_test_server_quit_unref (server);
	g_free (server2_uri);
	soup_test_server_quit_unref (server2);

	soup_test_session_abort_unref (async_session);
	soup_test_session_abort_unref (sync_session);

	return ret;
}
