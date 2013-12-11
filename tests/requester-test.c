/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2011 Red Hat, Inc.
 */

/* Kill SoupRequester-related deprecation warnings */
#define SOUP_VERSION_MIN_REQUIRED SOUP_VERSION_2_40

#include "test-utils.h"

SoupServer *server;
GMainLoop *loop;
char buf[1024];

SoupBuffer *response, *auth_response;

#define REDIRECT_HTML_BODY "<html><body>Try again</body></html>\r\n"
#define AUTH_HTML_BODY "<html><body>Unauthorized</body></html>\r\n"

static void
get_index (void)
{
	char *contents;
	gsize length;
	GError *error = NULL;

	if (!g_file_get_contents (SRCDIR "/index.txt", &contents, &length, &error)) {
		g_printerr ("Could not read index.txt: %s\n",
			    error->message);
		exit (1);
	}

	response = soup_buffer_new (SOUP_MEMORY_TAKE, contents, length);

	auth_response = soup_buffer_new (SOUP_MEMORY_STATIC,
					 AUTH_HTML_BODY,
					 strlen (AUTH_HTML_BODY));
}

static gboolean
slow_finish_message (gpointer msg)
{
	SoupServer *server = g_object_get_data (G_OBJECT (msg), "server");

	soup_server_unpause_message (server, msg);
	return FALSE;
}

static void
slow_pause_message (SoupMessage *msg, gpointer server)
{
	soup_server_pause_message (server, msg);
	soup_add_timeout (soup_server_get_async_context (server),
			  1000, slow_finish_message, msg);
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	gboolean chunked = FALSE;
	int i;

	if (strcmp (path, "/auth") == 0) {
		soup_message_set_status (msg, SOUP_STATUS_UNAUTHORIZED);
		soup_message_set_response (msg, "text/html",
					   SOUP_MEMORY_STATIC,
					   AUTH_HTML_BODY,
					   strlen (AUTH_HTML_BODY));
		soup_message_headers_append (msg->response_headers,
					     "WWW-Authenticate",
					     "Basic: realm=\"requester-test\"");
		return;
	} else if (strcmp (path, "/foo") == 0) {
		soup_message_set_redirect (msg, SOUP_STATUS_FOUND, "/");
		/* Make the response HTML so if we sniff that instead of the
		 * real body, we'll notice.
		 */
		soup_message_set_response (msg, "text/html",
					   SOUP_MEMORY_STATIC,
					   REDIRECT_HTML_BODY,
					   strlen (REDIRECT_HTML_BODY));
		return;
	} else if (strcmp (path, "/chunked") == 0) {
		chunked = TRUE;
	} else if (strcmp (path, "/non-persistent") == 0) {
		soup_message_headers_append (msg->response_headers,
					     "Connection", "close");
	} else if (!strcmp (path, "/slow")) {
		g_object_set_data (G_OBJECT (msg), "server", server);
		g_signal_connect (msg, "wrote-headers",
				  G_CALLBACK (slow_pause_message), server);
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);

	if (chunked) {
		soup_message_headers_set_encoding (msg->response_headers,
						   SOUP_ENCODING_CHUNKED);

		for (i = 0; i < response->length; i += 8192) {
			SoupBuffer *tmp;

			tmp = soup_buffer_new_subbuffer (response, i,
							 MIN (8192, response->length - i));
			soup_message_body_append_buffer (msg->response_body, tmp);
			soup_buffer_free (tmp);
		}
		soup_message_body_complete (msg->response_body);
	} else
		soup_message_body_append_buffer (msg->response_body, response);
}

typedef struct {
	GString *body;
	gboolean cancel;
} RequestData;

static void
stream_closed (GObject *source, GAsyncResult *res, gpointer user_data)
{
	GInputStream *stream = G_INPUT_STREAM (source);
	GError *error = NULL;

	if (!g_input_stream_close_finish (stream, res, &error)) {
		debug_printf (1, "    close failed: %s\n", error->message);
		g_error_free (error);
		errors++;
	}
	g_main_loop_quit (loop);
	g_object_unref (stream);
}

static void
test_read_ready (GObject *source, GAsyncResult *res, gpointer user_data)
{
	GInputStream *stream = G_INPUT_STREAM (source);
	RequestData *data = user_data;
	GString *body = data->body;
	GError *error = NULL;
	gsize nread;

	nread = g_input_stream_read_finish (stream, res, &error);
	if (nread == -1) {
		debug_printf (1, "    read_async failed: %s\n", error->message);
		g_error_free (error);
		errors++;
		g_input_stream_close (stream, NULL, NULL);
		g_object_unref (stream);
		g_main_loop_quit (loop);
		return;
	} else if (nread == 0) {
		g_input_stream_close_async (stream,
					    G_PRIORITY_DEFAULT, NULL,
					    stream_closed, NULL);
		return;
	}

	g_string_append_len (body, buf, nread);
	g_input_stream_read_async (stream, buf, sizeof (buf),
				   G_PRIORITY_DEFAULT, NULL,
				   test_read_ready, data);
}

static void
auth_test_sent (GObject *source, GAsyncResult *res, gpointer user_data)
{
	RequestData *data = user_data;
	GInputStream *stream;
	GError *error = NULL;
	SoupMessage *msg;
	const char *content_type;

	stream = soup_request_send_finish (SOUP_REQUEST (source), res, &error);
	if (!stream) {
		debug_printf (1, "    send_async failed: %s\n", error->message);
		g_clear_error (&error);
		errors++;
		g_main_loop_quit (loop);
		return;
	}

	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (source));
	if (msg->status_code != SOUP_STATUS_UNAUTHORIZED) {
		debug_printf (1, "    GET failed: %d %s\n", msg->status_code,
			      msg->reason_phrase);
		errors++;
		g_main_loop_quit (loop);
		return;
	}
	g_object_unref (msg);

	content_type = soup_request_get_content_type (SOUP_REQUEST (source));
	if (g_strcmp0 (content_type, "text/html") != 0) {
		debug_printf (1, "    failed to sniff Content-Type: got %s\n",
			      content_type ? content_type : "(NULL)");
		errors++;
	}

	g_input_stream_read_async (stream, buf, sizeof (buf),
				   G_PRIORITY_DEFAULT, NULL,
				   test_read_ready, data);
}

static void
test_sent (GObject *source, GAsyncResult *res, gpointer user_data)
{
	RequestData *data = user_data;
	GInputStream *stream;
	GError *error = NULL;
	const char *content_type;

	stream = soup_request_send_finish (SOUP_REQUEST (source), res, &error);
	if (data->cancel) {
		if (stream) {
			debug_printf (1, "    send_async succeeded??\n");
			errors++;
			g_input_stream_close (stream, NULL, NULL);
			g_object_unref (stream);
		} else if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			debug_printf (1, "    send_async failed with wrong error: %s\n", error->message);
			errors++;
		}
		g_clear_error (&error);
		g_main_loop_quit (loop);
		return;
	} else {
		if (!stream) {
			debug_printf (1, "    send_async failed: %s\n", error->message);
			errors++;
			g_main_loop_quit (loop);
			g_clear_error (&error);
			return;
		}
	}

	content_type = soup_request_get_content_type (SOUP_REQUEST (source));
	if (g_strcmp0 (content_type, "text/plain") != 0) {
		debug_printf (1, "    failed to sniff Content-Type: got %s\n",
			      content_type ? content_type : "(NULL)");
		errors++;
	}

	g_input_stream_read_async (stream, buf, sizeof (buf),
				   G_PRIORITY_DEFAULT, NULL,
				   test_read_ready, data);
}

static void
cancel_message (SoupMessage *msg, gpointer session)
{
	soup_session_cancel_message (session, msg, SOUP_STATUS_FORBIDDEN);
}

static void
request_started (SoupSession *session, SoupMessage *msg,
		 SoupSocket *socket, gpointer user_data)
{
	SoupSocket **save_socket = user_data;

	g_clear_object (save_socket);
	*save_socket = g_object_ref (socket);
}

static void
do_async_test (SoupSession *session, SoupURI *uri,
	       GAsyncReadyCallback callback, guint expected_status,
	       SoupBuffer *expected_response,
	       gboolean persistent, gboolean cancel)
{
	SoupRequester *requester;
	SoupRequest *request;
	guint started_id;
	SoupSocket *socket = NULL;
	SoupMessage *msg;
	RequestData data;

	if (SOUP_IS_SESSION_ASYNC (session))
		requester = SOUP_REQUESTER (soup_session_get_feature (session, SOUP_TYPE_REQUESTER));
	else
		requester = NULL;

	data.body = g_string_new (NULL);
	data.cancel = cancel;
	if (requester)
		request = soup_requester_request_uri (requester, uri, NULL);
	else
		request = soup_session_request_uri (session, uri, NULL);
	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (request));

	if (cancel) {
		g_signal_connect (msg, "got-headers",
				  G_CALLBACK (cancel_message), session);
	}

	started_id = g_signal_connect (session, "request-started",
				       G_CALLBACK (request_started),
				       &socket);

	soup_request_send_async (request, NULL, callback, &data);
	g_object_unref (request);

	loop = g_main_loop_new (soup_session_get_async_context (session), TRUE);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	g_signal_handler_disconnect (session, started_id);

	if (msg->status_code != expected_status) {
		debug_printf (1, "    GET failed: %d %s (expected %d)\n",
			      msg->status_code, msg->reason_phrase,
			      expected_status);
		g_object_unref (msg);
		g_object_unref (socket);
		errors++;
		return;
	}
	g_object_unref (msg);

	if (!expected_response) {
		if (data.body->len) {
			debug_printf (1, "    body length mismatch: expected 0, got %d\n",
				      (int)data.body->len);
			errors++;
		}
	} else if (data.body->len != expected_response->length) {
		debug_printf (1, "    body length mismatch: expected %d, got %d\n",
			      (int)expected_response->length, (int)data.body->len);
		errors++;
	} else if (memcmp (data.body->str, expected_response->data,
			   expected_response->length) != 0) {
		debug_printf (1, "    body data mismatch\n");
		errors++;
	}

	if (persistent) {
		if (!soup_socket_is_connected (socket)) {
			debug_printf (1, "    socket not still connected!\n");
			errors++;
		}
	} else {
		if (soup_socket_is_connected (socket)) {
			debug_printf (1, "    socket still connected!\n");
			errors++;
		}
	}
	g_object_unref (socket);

	g_string_free (data.body, TRUE);
}

static void
do_test_for_thread_and_context (SoupSession *session, SoupURI *base_uri)
{
	SoupRequester *requester;
	SoupURI *uri;

	if (SOUP_IS_SESSION_ASYNC (session)) {
		requester = soup_requester_new ();
		soup_session_add_feature (session, SOUP_SESSION_FEATURE (requester));
		g_object_unref (requester);
	}
	soup_session_add_feature_by_type (session, SOUP_TYPE_CONTENT_SNIFFER);

	debug_printf (1, "    basic test\n");
	do_async_test (session, base_uri, test_sent,
		       SOUP_STATUS_OK, response,
		       TRUE, FALSE);

	debug_printf (1, "    chunked test\n");
	uri = soup_uri_new_with_base (base_uri, "/chunked");
	do_async_test (session, uri, test_sent,
		       SOUP_STATUS_OK, response,
		       TRUE, FALSE);
	soup_uri_free (uri);

	debug_printf (1, "    auth test\n");
	uri = soup_uri_new_with_base (base_uri, "/auth");
	do_async_test (session, uri, auth_test_sent,
		       SOUP_STATUS_UNAUTHORIZED, auth_response,
		       TRUE, FALSE);
	soup_uri_free (uri);

	debug_printf (1, "    non-persistent test\n");
	uri = soup_uri_new_with_base (base_uri, "/non-persistent");
	do_async_test (session, uri, test_sent,
		       SOUP_STATUS_OK, response,
		       FALSE, FALSE);
	soup_uri_free (uri);

	debug_printf (1, "    cancellation test\n");
	uri = soup_uri_new_with_base (base_uri, "/");
	do_async_test (session, uri, test_sent,
		       SOUP_STATUS_FORBIDDEN, NULL,
		       FALSE, TRUE);
	soup_uri_free (uri);
}

static void
do_simple_tests (SoupURI *uri)
{
	SoupSession *session;

	debug_printf (1, "Simple streaming test\n");

	debug_printf (1, "  SoupSession\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	do_test_for_thread_and_context (session, uri);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  SoupSessionAsync\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	do_test_for_thread_and_context (session, uri);
	soup_test_session_abort_unref (session);
}

static void
do_test_with_context_and_type (SoupURI *uri, gboolean plain_session)
{
	GMainContext *async_context;
	SoupSession *session;

	async_context = g_main_context_new ();
	g_main_context_push_thread_default (async_context);

	session = soup_test_session_new (plain_session ? SOUP_TYPE_SESSION : SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_ASYNC_CONTEXT, async_context,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);

	do_test_for_thread_and_context (session, uri);
	soup_test_session_abort_unref (session);

	g_main_context_pop_thread_default (async_context);
	g_main_context_unref (async_context);
}

static gpointer
do_test_with_context (gpointer uri)
{
	debug_printf (1, "  SoupSessionAsync\n");
	do_test_with_context_and_type (uri, FALSE);
	return NULL;
}

static gpointer
do_plain_test_with_context (gpointer uri)
{
	debug_printf (1, "  SoupSession\n");
	do_test_with_context_and_type (uri, TRUE);
	return NULL;
}

static void
do_context_tests (SoupURI *uri)
{
	debug_printf (1, "\nStreaming with a non-default-context\n");

	do_plain_test_with_context ((gpointer)uri);
	do_test_with_context ((gpointer)uri);
}

static void
do_thread_tests (SoupURI *uri)
{
	GThread *thread;

	debug_printf (1, "\nStreaming in another thread\n");

	thread = g_thread_new ("do_test_with_context",
			       do_plain_test_with_context,
			       uri);
	g_thread_join (thread);

	thread = g_thread_new ("do_test_with_context",
			       do_test_with_context,
			       uri);
	g_thread_join (thread);
}

static void
do_sync_request (SoupSession *session, SoupRequest *request,
		 guint expected_status, SoupBuffer *expected_response,
		 gboolean persistent, gboolean cancel)
{
	GInputStream *in;
	SoupMessage *msg;
	GError *error = NULL;
	GString *body;
	char buf[1024];
	gssize nread;
	guint started_id;
	SoupSocket *socket = NULL;

	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (request));
	if (cancel) {
		g_signal_connect (msg, "got-headers",
				  G_CALLBACK (cancel_message), session);
	}

	started_id = g_signal_connect (session, "request-started",
				       G_CALLBACK (request_started),
				       &socket);

	in = soup_request_send (request, NULL, &error);
	g_signal_handler_disconnect (session, started_id);
	if (cancel) {
		if (in) {
			debug_printf (1, "    send succeeded??\n");
			errors++;
			g_input_stream_close (in, NULL, NULL);
			g_object_unref (in);
		} else if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			debug_printf (1, "    send failed with wrong error: %s\n", error->message);
			errors++;
		}
		g_clear_error (&error);
		g_object_unref (msg);
		g_object_unref (socket);
		return;
	} else if (!in) {
		debug_printf (1, "    soup_request_send failed: %s\n",
			      error->message);
		g_object_unref (msg);
		g_clear_error (&error);
		g_object_unref (socket);
		errors++;
		return;
	}

	if (msg->status_code != expected_status) {
		debug_printf (1, "    GET failed: %d %s\n", msg->status_code,
			      msg->reason_phrase);
		g_object_unref (msg);
		g_object_unref (in);
		g_object_unref (socket);
		errors++;
		return;
	}
	g_object_unref (msg);

	body = g_string_new (NULL);
	do {
		nread = g_input_stream_read (in, buf, sizeof (buf),
					     NULL, &error);
		if (nread == -1) {
			debug_printf (1, "    g_input_stream_read failed: %s\n",
				      error->message);
			g_clear_error (&error);
			errors++;
			break;
		}
		g_string_append_len (body, buf, nread);
	} while (nread > 0);

	if (!g_input_stream_close (in, NULL, &error)) {
		debug_printf (1, "    g_input_stream_close failed: %s\n",
			      error->message);
		g_clear_error (&error);
		errors++;
	}
	g_object_unref (in);

	if (!expected_response) {
		if (body->len) {
			debug_printf (1, "    body length mismatch: expected 0, got %d\n",
				      (int)body->len);
			errors++;
		}
	} else if (body->len != expected_response->length) {
		debug_printf (1, "    body length mismatch: expected %d, got %d\n",
			      (int)expected_response->length, (int)body->len);
		errors++;
	} else if (memcmp (body->str, expected_response->data, body->len) != 0) {
		debug_printf (1, "    body data mismatch\n");
		errors++;
	}

	if (persistent) {
		if (!soup_socket_is_connected (socket)) {
			debug_printf (1, "    socket not still connected!\n");
			errors++;
		}
	} else {
		if (soup_socket_is_connected (socket)) {
			debug_printf (1, "    socket still connected!\n");
			errors++;
		}
	}
	g_object_unref (socket);

	g_string_free (body, TRUE);
}

static void
do_sync_tests_for_session (SoupSession *session, SoupURI *base_uri)
{
	SoupRequester *requester;
	SoupRequest *request;
	SoupURI *uri;

	requester = SOUP_REQUESTER (soup_session_get_feature (session, SOUP_TYPE_REQUESTER));

	uri = soup_uri_copy (base_uri);

	debug_printf (1, "    basic test\n");
	if (requester)
		request = soup_requester_request_uri (requester, uri, NULL);
	else
		request = soup_session_request_uri (session, uri, NULL);
	do_sync_request (session, request,
			 SOUP_STATUS_OK, response,
			 TRUE, FALSE);
	g_object_unref (request);

	debug_printf (1, "    chunked test\n");
	soup_uri_set_path (uri, "/chunked");
	if (requester)
		request = soup_requester_request_uri (requester, uri, NULL);
	else
		request = soup_session_request_uri (session, uri, NULL);
	do_sync_request (session, request,
			 SOUP_STATUS_OK, response,
			 TRUE, FALSE);
	g_object_unref (request);

	debug_printf (1, "    auth test\n");
	soup_uri_set_path (uri, "/auth");
	if (requester)
		request = soup_requester_request_uri (requester, uri, NULL);
	else
		request = soup_session_request_uri (session, uri, NULL);
	do_sync_request (session, request,
			 SOUP_STATUS_UNAUTHORIZED, auth_response,
			 TRUE, FALSE);
	g_object_unref (request);

	debug_printf (1, "    non-persistent test\n");
	soup_uri_set_path (uri, "/non-persistent");
	if (requester)
		request = soup_requester_request_uri (requester, uri, NULL);
	else
		request = soup_session_request_uri (session, uri, NULL);
	do_sync_request (session, request,
			 SOUP_STATUS_OK, response,
			 FALSE, FALSE);
	g_object_unref (request);

	debug_printf (1, "    cancel test\n");
	soup_uri_set_path (uri, "/");
	if (requester)
		request = soup_requester_request_uri (requester, uri, NULL);
	else
		request = soup_session_request_uri (session, uri, NULL);
	do_sync_request (session, request,
			 SOUP_STATUS_FORBIDDEN, NULL,
			 TRUE, TRUE);
	g_object_unref (request);

	soup_uri_free (uri);
}

static void
do_sync_tests (SoupURI *uri)
{
	SoupSession *session;
	SoupRequester *requester;

	debug_printf (1, "\nSync streaming\n");

	debug_printf (1, "  SoupSession\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	do_sync_tests_for_session (session, uri);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  SoupSessionSync\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	requester = soup_requester_new ();
	soup_session_add_feature (session, SOUP_SESSION_FEATURE (requester));
	g_object_unref (requester);
	do_sync_tests_for_session (session, uri);
	soup_test_session_abort_unref (session);
}

static void
do_null_char_request (SoupSession *session, const char *encoded_data,
		      const char *expected_data, int expected_len)
{
	GError *error = NULL;
	GInputStream *stream;
	SoupRequest *request;
	SoupURI *uri;
	char *uri_string, buf[256];
	gsize nread;

	uri_string = g_strdup_printf ("data:text/html,%s", encoded_data);
	uri = soup_uri_new (uri_string);
	g_free (uri_string);

	request = soup_session_request_uri (session, uri, NULL);
	stream = soup_test_request_send (request, NULL, 0, &error);

	if (error) {
		debug_printf (1, "    could not send request: %s\n", error->message);
		errors++;
		g_error_free (error);
		g_object_unref (request);
		soup_uri_free (uri);
		return;
	}

	g_input_stream_read_all (stream, buf, sizeof (buf), &nread, NULL, &error);
	if (error) {
		debug_printf (1, "    could not read response: %s\n", error->message);
		errors++;
		g_clear_error (&error);
	}

	soup_test_request_close_stream (request, stream, NULL, &error);
	if (error) {
		debug_printf (1, "    could not close stream: %s\n", error->message);
		errors++;
		g_clear_error (&error);
	}

	if (nread != expected_len) {
		debug_printf (1, "    response length mismatch: expected %d, got %lu\n",
		              expected_len, (gulong)nread);
		errors++;
	} else if (memcmp (buf, expected_data, nread) != 0) {
		debug_printf (1, "    response data mismatch\n");
		errors++;
	}

	g_object_unref (stream);
	g_object_unref (request);
	soup_uri_free (uri);
}

static void
do_null_char_test_for_session (SoupSession *session)
{
	static struct {
		const char *encoded_data;
		const char *expected_data;
		int expected_len;
	} test_cases[] = {
		{ "%3Cscript%3Ea%3D'%00'%3C%2Fscript%3E", "<script>a='\0'</script>", 22 },
		{ "%00%3Cscript%3Ea%3D42%3C%2Fscript%3E", "\0<script>a=42</script>", 22 },
		{ "%3Cscript%3E%00%3Cbr%2F%3E%3C%2Fscript%3E%00", "<script>\0<br/></script>\0", 24 },
	};
	static int num_test_cases = G_N_ELEMENTS(test_cases);
	int i;

	for (i = 0; i < num_test_cases; i++) {
		do_null_char_request (session, test_cases[i].encoded_data,
				      test_cases[i].expected_data, test_cases[i].expected_len);
	}
}

static void
do_null_char_tests (void)
{
	SoupSession *session;

	debug_printf (1, "\nStreaming data URLs containing null chars\n");

	debug_printf (1, "  SoupSession\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	do_null_char_test_for_session (session);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  SoupSessionAsync\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	do_null_char_test_for_session (session);
	soup_test_session_abort_unref (session);
}

static void
close_test_msg_finished (SoupMessage *msg,
			 gpointer     user_data)
{
	gboolean *finished = user_data;

	*finished = TRUE;
}

static void
do_close_test_for_session (SoupSession *session,
			   SoupURI     *uri)
{
	GError *error = NULL;
	GInputStream *stream;
	SoupRequest *request;
	guint64 start, end;
	GCancellable *cancellable;
	SoupMessage *msg;
	gboolean finished = FALSE;

	debug_printf (1, "    normal close\n");

	request = soup_session_request_uri (session, uri, NULL);
	stream = soup_test_request_send (request, NULL, 0, &error);

	if (error) {
		debug_printf (1, "      could not send request: %s\n", error->message);
		errors++;
		g_error_free (error);
		g_object_unref (request);
		return;
	}

	start = g_get_monotonic_time ();
	soup_test_request_close_stream (request, stream, NULL, &error);
	if (error) {
		debug_printf (1, "      could not close stream: %s\n", error->message);
		errors++;
		g_clear_error (&error);
	}
	end = g_get_monotonic_time ();

	if (end - start > 500000) {
		debug_printf (1, "      close() waited for response to complete!\n");
		errors++;
	}

	g_object_unref (stream);
	g_object_unref (request);


	debug_printf (1, "    error close\n");

	request = soup_session_request_uri (session, uri, NULL);
	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (request));
	g_signal_connect (msg, "finished", G_CALLBACK (close_test_msg_finished), &finished);
	g_object_unref (msg);

	stream = soup_test_request_send (request, NULL, 0, &error);
	if (error) {
		debug_printf (1, "      could not send request: %s\n", error->message);
		errors++;
		g_error_free (error);
		g_object_unref (request);
		return;
	}

	cancellable = g_cancellable_new ();
	g_cancellable_cancel (cancellable);
	soup_test_request_close_stream (request, stream, cancellable, &error);
	if (error && !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		debug_printf (1, "      did not get expected error: %s\n", error->message);
		errors++;
		g_clear_error (&error);
	}

	if (!finished) {
		debug_printf (1, "      message did not finish!\n");
		errors++;
	}

	g_object_unref (stream);
	g_object_unref (request);
}

static void
do_close_tests (SoupURI *uri)
{
	SoupSession *session;
	SoupURI *slow_uri;

	debug_printf (1, "\nClosing stream before end should cancel\n");

	slow_uri = soup_uri_new_with_base (uri, "/slow");

	debug_printf (1, "  SoupSessionAsync\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	do_close_test_for_session (session, slow_uri);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  SoupSessionSync\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	do_close_test_for_session (session, slow_uri);
	soup_test_session_abort_unref (session);

	soup_uri_free (slow_uri);
}

int
main (int argc, char **argv)
{
	SoupURI *uri;

	test_init (argc, argv, NULL);
	get_index ();

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);

	uri = soup_test_server_get_uri (server, "http", NULL);
	soup_uri_set_path (uri, "/foo");

	do_simple_tests (uri);
	do_thread_tests (uri);
	do_context_tests (uri);
	do_sync_tests (uri);
	do_null_char_tests ();
	do_close_tests (uri);

	soup_uri_free (uri);
	soup_buffer_free (response);
	soup_buffer_free (auth_response);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return errors != 0;
}
