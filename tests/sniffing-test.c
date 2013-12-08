/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2009 Gustavo Noronha Silva <gns@gnome.org>.
 */

#include "test-utils.h"

SoupSession *session;
SoupURI *base_uri;
SoupMessageBody *chunk_data;

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	GError *error = NULL;
	char *query_key;
	char *contents;
	gsize length = 0, offset;
	gboolean empty_response = FALSE;

	if (msg->method != SOUP_METHOD_GET) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);

	if (query) {
		query_key = g_hash_table_lookup (query, "chunked");
		if (query_key && g_str_equal (query_key, "yes")) {
			soup_message_headers_set_encoding (msg->response_headers,
							   SOUP_ENCODING_CHUNKED);
		}

		query_key = g_hash_table_lookup (query, "empty_response");
		if (query_key && g_str_equal (query_key, "yes"))
			empty_response = TRUE;
	}

	if (!strcmp (path, "/mbox")) {
		if (empty_response) {
			contents = g_strdup ("");
			length = 0;
		} else {
			g_file_get_contents (SRCDIR "/resources/mbox",
					     &contents, &length,
					     &error);
		}

		if (error) {
			g_error ("%s", error->message);
			g_error_free (error);
			exit (1);
		}

		soup_message_headers_append (msg->response_headers,
					     "Content-Type", "text/plain");
	}

	if (g_str_has_prefix (path, "/text_or_binary/") || g_str_has_prefix (path, "/apache_bug/")) {
		char *base_name = g_path_get_basename (path);
		char *file_name = g_strdup_printf (SRCDIR "/resources/%s", base_name);

		g_file_get_contents (file_name,
				     &contents, &length,
				     &error);

		g_free (base_name);
		g_free (file_name);

		if (error) {
			g_error ("%s", error->message);
			g_error_free (error);
			exit (1);
		}

		soup_message_headers_append (msg->response_headers,
					     "Content-Type", "text/plain");
	}

	if (g_str_has_prefix (path, "/unknown/")) {
		char *base_name = g_path_get_basename (path);
		char *file_name = g_strdup_printf (SRCDIR "/resources/%s", base_name);

		g_file_get_contents (file_name,
				     &contents, &length,
				     &error);

		g_free (base_name);
		g_free (file_name);

		if (error) {
			g_error ("%s", error->message);
			g_error_free (error);
			exit (1);
		}

		soup_message_headers_append (msg->response_headers,
					     "Content-Type", "UNKNOWN/unknown");
	}

	if (g_str_has_prefix (path, "/type/")) {
		char **components = g_strsplit (path, "/", 4);
		char *ptr;

		char *base_name = g_path_get_basename (path);
		char *file_name = g_strdup_printf (SRCDIR "/resources/%s", base_name);

		g_file_get_contents (file_name,
				     &contents, &length,
				     &error);

		g_free (base_name);
		g_free (file_name);

		if (error) {
			g_error ("%s", error->message);
			g_error_free (error);
			exit (1);
		}

		/* Hack to allow passing type in the URI */
		ptr = g_strrstr (components[2], "_");
		*ptr = '/';

		soup_message_headers_append (msg->response_headers,
					     "Content-Type", components[2]);
		g_strfreev (components);
	}

	if (g_str_has_prefix (path, "/multiple_headers/")) {
		char *base_name = g_path_get_basename (path);
		char *file_name = g_strdup_printf (SRCDIR "/resources/%s", base_name);

		g_file_get_contents (file_name,
				     &contents, &length,
				     &error);

		g_free (base_name);
		g_free (file_name);

		if (error) {
			g_error ("%s", error->message);
			g_error_free (error);
			exit (1);
		}

		soup_message_headers_append (msg->response_headers,
					     "Content-Type", "text/xml");
		soup_message_headers_append (msg->response_headers,
					     "Content-Type", "text/plain");
	}

	for (offset = 0; offset < length; offset += 500) {
		soup_message_body_append (msg->response_body,
					  SOUP_MEMORY_COPY,
					  contents + offset,
					  MIN(500, length - offset));
	}
	soup_message_body_complete (msg->response_body);

	g_free (contents);
}

static gboolean
unpause_msg (gpointer data)
{
	SoupMessage *msg = (SoupMessage*)data;
	debug_printf (2, "  unpause\n");
	soup_session_unpause_message (session, msg);
	return FALSE;
}


static void
content_sniffed (SoupMessage *msg, char *content_type, GHashTable *params, gpointer data)
{
	gboolean should_pause = GPOINTER_TO_INT (data);

	debug_printf (2, "  content-sniffed -> %s\n", content_type);

	if (g_object_get_data (G_OBJECT (msg), "got-chunk")) {
		debug_printf (1, "  got-chunk got emitted before content-sniffed\n");
		errors++;
	}

	g_object_set_data (G_OBJECT (msg), "content-sniffed", GINT_TO_POINTER (TRUE));

	if (should_pause) {
		debug_printf (2, "  pause\n");
		soup_session_pause_message (session, msg);
		g_idle_add (unpause_msg, msg);
	}
}

static void
got_headers (SoupMessage *msg, gpointer data)
{
	gboolean should_pause = GPOINTER_TO_INT (data);

	debug_printf (2, "  got-headers\n");

	if (g_object_get_data (G_OBJECT (msg), "content-sniffed")) {
		debug_printf (1, "  content-sniffed got emitted before got-headers\n");
		errors++;
	}

	g_object_set_data (G_OBJECT (msg), "got-headers", GINT_TO_POINTER (TRUE));

	if (should_pause) {
		debug_printf (2, "  pause\n");
		soup_session_pause_message (session, msg);
		g_idle_add (unpause_msg, msg);
	}
}

static void
got_chunk (SoupMessage *msg, SoupBuffer *chunk, gpointer data)
{
	gboolean should_accumulate = GPOINTER_TO_INT (data);

	debug_printf (2, "  got-chunk\n");

	g_object_set_data (G_OBJECT (msg), "got-chunk", GINT_TO_POINTER (TRUE));

	if (!should_accumulate) {
		if (!chunk_data)
			chunk_data = soup_message_body_new ();
		soup_message_body_append_buffer (chunk_data, chunk);
	}
}

static void
do_signals_test (gboolean should_content_sniff,
		 gboolean should_pause,
		 gboolean should_accumulate,
		 gboolean chunked_encoding,
		 gboolean empty_response)
{
	SoupURI *uri = soup_uri_new_with_base (base_uri, "/mbox");
	SoupMessage *msg = soup_message_new_from_uri ("GET", uri);
	char *contents;
	gsize length;
	GError *error = NULL;
	SoupBuffer *body = NULL;

	debug_printf (1, "do_signals_test(%ssniff, %spause, %saccumulate, %schunked, %sempty)\n",
		      should_content_sniff ? "" : "!",
		      should_pause ? "" : "!",
		      should_accumulate ? "" : "!",
		      chunked_encoding ? "" : "!",
		      empty_response ? "" : "!");

	if (chunked_encoding)
		soup_uri_set_query (uri, "chunked=yes");

	if (empty_response) {
		if (uri->query) {
			char *tmp = uri->query;
			uri->query = g_strdup_printf ("%s&empty_response=yes", tmp);
			g_free (tmp);
		} else
			soup_uri_set_query (uri, "empty_response=yes");
	}

	soup_message_set_uri (msg, uri);

	soup_message_body_set_accumulate (msg->response_body, should_accumulate);

	g_object_connect (msg,
			  "signal::got-headers", got_headers, GINT_TO_POINTER (should_pause),
			  "signal::got-chunk", got_chunk, GINT_TO_POINTER (should_accumulate),
			  "signal::content_sniffed", content_sniffed, GINT_TO_POINTER (should_pause),
			  NULL);

	soup_session_send_message (session, msg);

	if (!should_content_sniff &&
	    g_object_get_data (G_OBJECT (msg), "content-sniffed")) {
		debug_printf (1, "  content-sniffed got emitted without a sniffer\n");
		errors++;
	} else if (should_content_sniff &&
		   !g_object_get_data (G_OBJECT (msg), "content-sniffed")) {
		debug_printf (1, "  content-sniffed did not get emitted\n");
		errors++;
	}

	if (empty_response) {
		contents = g_strdup ("");
		length = 0;
	} else {
		g_file_get_contents (SRCDIR "/resources/mbox",
				     &contents, &length,
				     &error);
	}

	if (error) {
		g_error ("%s", error->message);
		g_error_free (error);
		exit (1);
	}

	if (!should_accumulate && chunk_data)
		body = soup_message_body_flatten (chunk_data);
	else if (msg->response_body)
		body = soup_message_body_flatten (msg->response_body);

	if (body && body->length != length) {
		debug_printf (1, "  lengths do not match\n");
		errors++;
	}

	if (body && memcmp (body->data, contents, length)) {
		debug_printf (1, "  downloaded data does not match\n");
		errors++;
	}

	g_free (contents);
	if (body)
		soup_buffer_free (body);
	if (chunk_data) {
		soup_message_body_free (chunk_data);
		chunk_data = NULL;
	}

	soup_uri_free (uri);
	g_object_unref (msg);
}

static void
sniffing_content_sniffed (SoupMessage *msg, const char *content_type,
			  GHashTable *params, gpointer data)
{
	char **sniffed_type = (char **)data;
	GString *full_header;
	GHashTableIter iter;
	gpointer key, value;

	full_header = g_string_new (content_type);

	g_hash_table_iter_init (&iter, params);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		if (full_header->len)
			g_string_append (full_header, "; ");
		soup_header_g_string_append_param (full_header,
						   (const char *) key,
						   (const char *) value);
	}

	*sniffed_type = g_string_free (full_header, FALSE);
}

static void
test_sniffing (const char *path, const char *expected_type)
{
	SoupURI *uri;
	SoupMessage *msg;
	SoupRequest *req;
	GInputStream *stream;
	char *sniffed_type = NULL;
	GError *error = NULL;

	debug_printf (1, "test_sniffing(\"%s\", \"%s\")\n", path, expected_type);

	uri = soup_uri_new_with_base (base_uri, path);
	msg = soup_message_new_from_uri ("GET", uri);

	g_signal_connect (msg, "content-sniffed",
			  G_CALLBACK (sniffing_content_sniffed), &sniffed_type);

	soup_session_send_message (session, msg);
	if (!sniffed_type) {
		debug_printf (1, "  message was not sniffed!\n");
		errors++;
	} else if (strcmp (sniffed_type, expected_type) != 0) {
		debug_printf (1, "  message sniffing failed! expected %s, got %s\n",
			      expected_type, sniffed_type);
		errors++;
	}
	g_free (sniffed_type);
	g_object_unref (msg);

	req = soup_session_request_uri (session, uri, NULL);
	stream = soup_test_request_send (req, NULL, 0, &error);
	if (stream) {
		soup_test_request_close_stream (req, stream, NULL, &error);
		g_object_unref (stream);
	}
	if (error) {
		debug_printf (1, "  request failed: %s\n", error->message);
		g_clear_error (&error);
	} else {
		const char *req_sniffed_type;

		req_sniffed_type = soup_request_get_content_type (req);
		if (strcmp (req_sniffed_type, expected_type) != 0) {
			debug_printf (1, "  request sniffing failed! expected %s, got %s\n",
				      expected_type, req_sniffed_type);
			errors++;
		}
	}
	g_object_unref (req);

	soup_uri_free (uri);
}

static void
test_disabled (const char *path)
{
	SoupURI *uri;
	SoupMessage *msg;
	SoupRequest *req;
	GInputStream *stream;
	char *sniffed_type = NULL;
	GError *error = NULL;

	debug_printf (1, "test_disabled(\"%s\")\n", path);

	uri = soup_uri_new_with_base (base_uri, path);

	msg = soup_message_new_from_uri ("GET", uri);
	soup_message_disable_feature (msg, SOUP_TYPE_CONTENT_SNIFFER);

	g_signal_connect (msg, "content-sniffed",
			  G_CALLBACK (sniffing_content_sniffed), &sniffed_type);

	soup_session_send_message (session, msg);

	if (sniffed_type) {
		debug_printf (1, "  message was sniffed!\n");
		errors++;
		g_free (sniffed_type);
	}
	g_object_unref (msg);

	req = soup_session_request_uri (session, uri, NULL);
	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (req));
	soup_message_disable_feature (msg, SOUP_TYPE_CONTENT_SNIFFER);
	g_object_unref (msg);
	stream = soup_test_request_send (req, NULL, 0, &error);
	if (stream) {
		soup_test_request_close_stream (req, stream, NULL, &error);
		g_object_unref (stream);
	}
	if (error) {
		debug_printf (1, "  request failed: %s\n", error->message);
		g_clear_error (&error);
	} else {
		const char *sniffed_content_type;

		sniffed_content_type = soup_request_get_content_type (req);
		if (sniffed_content_type != NULL) {
			debug_printf (1, "  request was sniffed!\n");
			errors++;
		}
	}
	g_object_unref (req);

	soup_uri_free (uri);
}

int
main (int argc, char **argv)
{
	SoupServer *server;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_uri_new ("http://127.0.0.1/");
	soup_uri_set_port (base_uri, soup_server_get_port (server));

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);

	/* No sniffer, no content_sniffed should be emitted */
	do_signals_test (FALSE, FALSE, FALSE, FALSE, FALSE);
	do_signals_test (FALSE, FALSE, FALSE, TRUE, FALSE);
	do_signals_test (FALSE, FALSE, TRUE, FALSE, FALSE);
	do_signals_test (FALSE, FALSE, TRUE, TRUE, FALSE);

	do_signals_test (FALSE, TRUE, TRUE, FALSE, FALSE);
	do_signals_test (FALSE, TRUE, TRUE, TRUE, FALSE);
	do_signals_test (FALSE, TRUE, FALSE, FALSE, FALSE);
	do_signals_test (FALSE, TRUE, FALSE, TRUE, FALSE);

	/* Tests that the signals are correctly emitted for empty
	 * responses; see
	 * http://bugzilla.gnome.org/show_bug.cgi?id=587907 */

	do_signals_test (FALSE, TRUE, TRUE, FALSE, TRUE);
	do_signals_test (FALSE, TRUE, TRUE, TRUE, TRUE);

	soup_session_add_feature_by_type (session, SOUP_TYPE_CONTENT_SNIFFER);

	/* Now, with a sniffer, content_sniffed must be emitted after
	 * got-headers, and before got-chunk.
	 */
	do_signals_test (TRUE, FALSE, FALSE, FALSE, FALSE);
	do_signals_test (TRUE, FALSE, FALSE, TRUE, FALSE);
	do_signals_test (TRUE, FALSE, TRUE, FALSE, FALSE);
	do_signals_test (TRUE, FALSE, TRUE, TRUE, FALSE);

	do_signals_test (TRUE, TRUE, TRUE, FALSE, FALSE);
	do_signals_test (TRUE, TRUE, TRUE, TRUE, FALSE);
	do_signals_test (TRUE, TRUE, FALSE, FALSE, FALSE);
	do_signals_test (TRUE, TRUE, FALSE, TRUE, FALSE);

	/* Empty response tests */
	do_signals_test (TRUE, TRUE, TRUE, FALSE, TRUE);
	do_signals_test (TRUE, TRUE, TRUE, TRUE, TRUE);

	/* Test the apache bug sniffing path */

	test_sniffing ("/apache_bug/text_binary.txt", "application/octet-stream");
	test_sniffing ("/apache_bug/text.txt", "text/plain");

	/* GIF is a 'safe' type */
	test_sniffing ("/text_or_binary/home.gif", "image/gif");

	/* With our current code, no sniffing is done using GIO, so
	 * the mbox will be identified as text/plain; should we change
	 * this?
	 */
	test_sniffing ("/text_or_binary/mbox", "text/plain");

	/* HTML is considered unsafe for this algorithm, since it is
	 * scriptable, so going from text/plain to text/html is
	 * considered 'privilege escalation'
	 */
	test_sniffing ("/text_or_binary/test.html", "text/plain");

	/* text/plain with binary content and unknown pattern should be
	 * application/octet-stream */
	test_sniffing ("/text_or_binary/text_binary.txt", "application/octet-stream");

	/* text/plain with binary content and scriptable pattern should be
	 * application/octet-stream to avoid 'privilege escalation' */
	test_sniffing ("/text_or_binary/html_binary.html", "application/octet-stream");

	/* text/plain with binary content and non scriptable known pattern should
	 * be the given type */
	test_sniffing ("/text_or_binary/ps_binary.ps", "application/postscript");

	/* Test the unknown sniffing path */

	test_sniffing ("/unknown/test.html", "text/html");
	test_sniffing ("/unknown/home.gif", "image/gif");
	test_sniffing ("/unknown/mbox", "text/plain");
	test_sniffing ("/unknown/text_binary.txt", "application/octet-stream");

	/* Test the XML sniffing path */

	test_sniffing ("/type/text_xml/home.gif", "text/xml");
	test_sniffing ("/type/anice_type+xml/home.gif", "anice/type+xml");
	test_sniffing ("/type/application_xml/home.gif", "application/xml");

	/* Test the image sniffing path */

	test_sniffing ("/type/image_png/home.gif", "image/gif");

	/* Test the feed or html path */

	test_sniffing ("/type/text_html/test.html", "text/html");
	test_sniffing ("/type/text_html/rss20.xml", "application/rss+xml");
	test_sniffing ("/type/text_html/atom.xml", "application/atom+xml");

	/* The spec tells us to only use the last Content-Type header */

	test_sniffing ("/multiple_headers/home.gif", "image/gif");

	/* Test that we keep the parameters when sniffing */
	test_sniffing ("/type/text_html; charset=UTF-8/test.html", "text/html; charset=UTF-8");

	/* Test that disabling the sniffer works correctly */

	test_disabled ("/text_or_binary/home.gif");

	soup_uri_free (base_uri);

	soup_test_session_abort_unref (session);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return errors != 0;
}
