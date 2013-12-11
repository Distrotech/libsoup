/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2012 Red Hat, Inc.
 */

#include "test-utils.h"

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	const char *last_modified, *etag;
	const char *header;
	guint status = SOUP_STATUS_OK;

	if (msg->method != SOUP_METHOD_GET && msg->method != SOUP_METHOD_POST) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	header = soup_message_headers_get_one (msg->request_headers,
					       "Test-Set-Expires");
	if (header) {
		soup_message_headers_append (msg->response_headers,
					     "Expires",
					     header);
	}

	header = soup_message_headers_get_one (msg->request_headers,
					       "Test-Set-Cache-Control");
	if (header) {
		soup_message_headers_append (msg->response_headers,
					     "Cache-Control",
					     header);
	}

	last_modified = soup_message_headers_get_one (msg->request_headers,
						      "Test-Set-Last-Modified");
	if (last_modified) {
		soup_message_headers_append (msg->response_headers,
					     "Last-Modified",
					     last_modified);
	}

	etag = soup_message_headers_get_one (msg->request_headers,
					     "Test-Set-ETag");
	if (etag) {
		soup_message_headers_append (msg->response_headers,
					     "ETag",
					     etag);
	}


	header = soup_message_headers_get_one (msg->request_headers,
					       "If-Modified-Since");
	if (header && last_modified) {
		SoupDate *date;
		time_t lastmod, check;

		date = soup_date_new_from_string (last_modified);
		lastmod = soup_date_to_time_t (date);
		soup_date_free (date);

		date = soup_date_new_from_string (header);
		check = soup_date_to_time_t (date);
		soup_date_free (date);

		if (lastmod <= check)
			status = SOUP_STATUS_NOT_MODIFIED;
	}

	header = soup_message_headers_get_one (msg->request_headers,
					       "If-None-Match");
	if (header && etag) {
		if (!strcmp (header, etag))
			status = SOUP_STATUS_NOT_MODIFIED;
	}

	header = soup_message_headers_get_one (msg->request_headers,
					       "Test-Set-My-Header");
	if (header) {
		soup_message_headers_append (msg->response_headers,
					     "My-Header",
					     header);
	}

	if (status == SOUP_STATUS_OK) {
		GChecksum *sum;
		const char *body;

		sum = g_checksum_new (G_CHECKSUM_SHA256);
		g_checksum_update (sum, (guchar *)path, strlen (path));
		if (last_modified)
			g_checksum_update (sum, (guchar *)last_modified, strlen (last_modified));
		if (etag)
			g_checksum_update (sum, (guchar *)etag, strlen (etag));
		body = g_checksum_get_string (sum);
		soup_message_set_response (msg, "text/plain",
					   SOUP_MEMORY_COPY,
					   body, strlen (body) + 1);
		g_checksum_free (sum);
	}
	soup_message_set_status (msg, status);
}

static gboolean
is_network_stream (GInputStream *stream)
{
	while (G_IS_FILTER_INPUT_STREAM (stream))
		stream = G_FILTER_INPUT_STREAM (stream)->base_stream;

	return !G_IS_FILE_INPUT_STREAM (stream);
}

static char *do_request (SoupSession        *session,
			 SoupURI            *base_uri,
			 const char         *method,
			 const char         *path,
			 SoupMessageHeaders *response_headers,
			 ...) G_GNUC_NULL_TERMINATED;

static gboolean last_request_hit_network;
static gboolean last_request_validated;
static guint cancelled_requests;

static void
copy_headers (const char         *name,
	      const char         *value,
	      gpointer            user_data)
{
	SoupMessageHeaders *headers = (SoupMessageHeaders *) user_data;
	soup_message_headers_append (headers, name, value);
}

static char *
do_request (SoupSession        *session,
	    SoupURI            *base_uri,
	    const char         *method,
	    const char         *path,
	    SoupMessageHeaders *response_headers,
	    ...)
{
	SoupRequestHTTP *req;
	SoupMessage *msg;
	GInputStream *stream;
	SoupURI *uri;
	va_list ap;
	const char *header, *value;
	char buf[256];
	gsize nread;
	GError *error = NULL;

	last_request_validated = last_request_hit_network = FALSE;

	uri = soup_uri_new_with_base (base_uri, path);
	req = soup_session_request_http_uri (session, method, uri, NULL);
	soup_uri_free (uri);
	msg = soup_request_http_get_message (req);

	va_start (ap, response_headers);
	while ((header = va_arg (ap, const char *))) {
		value = va_arg (ap, const char *);
		soup_message_headers_append (msg->request_headers,
					     header, value);
	}
	va_end (ap);

	stream = soup_test_request_send (SOUP_REQUEST (req), NULL, 0, &error);
	if (!stream) {
		debug_printf (1, "    could not send request: %s\n",
			      error->message);
		g_error_free (error);
		g_object_unref (req);
		g_object_unref (msg);
		return NULL;
	}

	if (response_headers)
		soup_message_headers_foreach (msg->response_headers, copy_headers, response_headers);

	g_object_unref (msg);

	last_request_hit_network = is_network_stream (stream);

	g_input_stream_read_all (stream, buf, sizeof (buf), &nread,
				 NULL, &error);
	if (error) {
		debug_printf (1, "    could not read response: %s\n",
			      error->message);
		g_clear_error (&error);
	}
	soup_test_request_close_stream (SOUP_REQUEST (req), stream,
					NULL, &error);
	if (error) {
		debug_printf (1, "    could not close stream: %s\n",
			      error->message);
		g_clear_error (&error);
	}
	g_object_unref (stream);
	g_object_unref (req);

	/* Cache writes are G_PRIORITY_LOW, so they won't have happened yet... */
	soup_cache_flush ((SoupCache *)soup_session_get_feature (session, SOUP_TYPE_CACHE));

	return nread ? g_memdup (buf, nread) : g_strdup ("");
}

static void
do_request_with_cancel (SoupSession          *session,
			SoupURI              *base_uri,
			const char           *method,
			const char           *path,
			SoupTestRequestFlags  flags)
{
	SoupRequestHTTP *req;
	GInputStream *stream;
	SoupURI *uri;
	GError *error = NULL;
	GCancellable *cancellable;

	last_request_validated = last_request_hit_network = FALSE;
	cancelled_requests = 0;

	uri = soup_uri_new_with_base (base_uri, path);
	req = soup_session_request_http_uri (session, method, uri, NULL);
	soup_uri_free (uri);
	cancellable = flags & SOUP_TEST_REQUEST_CANCEL_CANCELLABLE ? g_cancellable_new () : NULL;
	stream = soup_test_request_send (SOUP_REQUEST (req), cancellable, flags, &error);
	if (stream) {
		debug_printf (1, "    could not cancel the request\n");
		g_object_unref (stream);
		g_object_unref (req);
		return;
	}

	g_clear_object (&cancellable);
	g_clear_object (&stream);
	g_clear_object (&req);

	soup_cache_flush ((SoupCache *)soup_session_get_feature (session, SOUP_TYPE_CACHE));
}

static void
request_started (SoupSession *session, SoupMessage *msg,
		 SoupSocket *socket)
{
	if (soup_message_headers_get_one (msg->request_headers,
					  "If-Modified-Since") ||
	    soup_message_headers_get_one (msg->request_headers,
					  "If-None-Match")) {
		debug_printf (2, "    Conditional request for %s\n",
			      soup_message_get_uri (msg)->path);
		last_request_validated = TRUE;
	}
}

static void
request_unqueued (SoupSession *session, SoupMessage *msg,
		  gpointer data)
{
	if (msg->status_code == SOUP_STATUS_CANCELLED)
		cancelled_requests++;
}

static void
do_basics_test (SoupURI *base_uri)
{
	SoupSession *session;
	SoupCache *cache;
	char *cache_dir;
	char *body1, *body2, *body3, *body4, *body5, *cmp;

	debug_printf (1, "Cache basics\n");

	cache_dir = g_dir_make_tmp ("cache-test-XXXXXX", NULL);
	debug_printf (2, "  Caching to %s\n", cache_dir);
	cache = soup_cache_new (cache_dir, SOUP_CACHE_SINGLE_USER);
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 SOUP_SESSION_ADD_FEATURE, cache,
					 NULL);
	g_signal_connect (session, "request-started",
			  G_CALLBACK (request_started), NULL);

	debug_printf (2, "  Initial requests\n");
	body1 = do_request (session, base_uri, "GET", "/1", NULL,
			    "Test-Set-Expires", "Fri, 01 Jan 2100 00:00:00 GMT",
			    NULL);
	body2 = do_request (session, base_uri, "GET", "/2", NULL,
			    "Test-Set-Last-Modified", "Fri, 01 Jan 2010 00:00:00 GMT",
			    NULL);
	body3 = do_request (session, base_uri, "GET", "/3", NULL,
			    "Test-Set-Last-Modified", "Fri, 01 Jan 2010 00:00:00 GMT",
			    "Test-Set-Cache-Control", "must-revalidate",
			    NULL);
	body4 = do_request (session, base_uri, "GET", "/4", NULL,
			    "Test-Set-ETag", "\"abcdefg\"",
			    "Test-Set-Cache-Control", "must-revalidate",
			    NULL);
	body5 = do_request (session, base_uri, "GET", "/5", NULL,
			    "Test-Set-Cache-Control", "no-cache",
			    NULL);


	/* Resource with future Expires should have been cached */
	debug_printf (1, "  Fresh cached resource\n");
	cmp = do_request (session, base_uri, "GET", "/1", NULL,
			  NULL);
	if (last_request_hit_network) {
		debug_printf (1, "    Request for /1 not filled from cache!\n");
		errors++;
	}
	if (strcmp (body1, cmp) != 0) {
		debug_printf (1, "    Cached response (%s) did not match original (%s)\n",
			      cmp, body1);
		errors++;
	}
	g_free (cmp);


	/* Resource with long-ago Last-Modified should have been cached */
	debug_printf (1, "  Heuristically-fresh cached resource\n");
	cmp = do_request (session, base_uri, "GET", "/2", NULL,
			  NULL);
	if (last_request_hit_network) {
		debug_printf (1, "    Request for /2 not filled from cache!\n");
		errors++;
	}
	if (strcmp (body2, cmp) != 0) {
		debug_printf (1, "    Cached response (%s) did not match original (%s)\n",
			      cmp, body2);
		errors++;
	}
	g_free (cmp);


	/* Adding a query string should bypass the cache but not invalidate it */
	debug_printf (1, "  Fresh cached resource with a query\n");
	cmp = do_request (session, base_uri, "GET", "/1?attr=value", NULL,
			  NULL);
	if (!last_request_hit_network) {
		debug_printf (1, "    Request for /1?attr=value filled from cache!\n");
		errors++;
	}
	g_free (cmp);
	debug_printf (2, "  Second request\n");
	cmp = do_request (session, base_uri, "GET", "/1", NULL,
			  NULL);
	if (last_request_hit_network) {
		debug_printf (1, "    Second request for /1 not filled from cache!\n");
		errors++;
	}
	if (strcmp (body1, cmp) != 0) {
		debug_printf (1, "    Cached response (%s) did not match original (%s)\n",
			      cmp, body1);
		errors++;
	}
	g_free (cmp);


	/* Last-Modified + must-revalidate causes a conditional request */
	debug_printf (1, "  Unchanged must-revalidate resource w/ Last-Modified\n");
	cmp = do_request (session, base_uri, "GET", "/3", NULL,
			  "Test-Set-Last-Modified", "Fri, 01 Jan 2010 00:00:00 GMT",
			  "Test-Set-Cache-Control", "must-revalidate",
			  NULL);
	if (!last_request_validated) {
		debug_printf (1, "    Request for /3 not validated!\n");
		errors++;
	}
	if (last_request_hit_network) {
		debug_printf (1, "    Request for /3 not filled from cache!\n");
		errors++;
	}
	if (strcmp (body3, cmp) != 0) {
		debug_printf (1, "    Cached response (%s) did not match original (%s)\n",
			      cmp, body3);
		errors++;
	}
	g_free (cmp);


	/* Validation failure should update cache */
	debug_printf (1, "  Changed must-revalidate resource w/ Last-Modified\n");
	cmp = do_request (session, base_uri, "GET", "/3", NULL,
			  "Test-Set-Last-Modified", "Sat, 02 Jan 2010 00:00:00 GMT",
			  "Test-Set-Cache-Control", "must-revalidate",
			  NULL);
	if (!last_request_validated) {
		debug_printf (1, "    Request for /3 not validated!\n");
		errors++;
	}
	if (!last_request_hit_network) {
		debug_printf (1, "    Request for /3 filled from cache!\n");
		errors++;
	}
	if (strcmp (body3, cmp) == 0) {
		debug_printf (1, "    Request for /3 returned cached response\n");
		errors++;
	}
	g_free (cmp);

	debug_printf (2, "  Second request\n");
	cmp = do_request (session, base_uri, "GET", "/3", NULL,
			  "Test-Set-Last-Modified", "Sat, 02 Jan 2010 00:00:00 GMT",
			  "Test-Set-Cache-Control", "must-revalidate",
			  NULL);
	if (!last_request_validated) {
		debug_printf (1, "    Second request for /3 not validated!\n");
		errors++;
	}
	if (last_request_hit_network) {
		debug_printf (1, "    Second request for /3 not filled from cache!\n");
		errors++;
	}
	if (strcmp (body3, cmp) == 0) {
		debug_printf (1, "    Replacement body for /3 not cached!\n");
		errors++;
	}
	g_free (cmp);

	/* ETag + must-revalidate causes a conditional request */
	debug_printf (1, "  Unchanged must-revalidate resource w/ ETag\n");
	cmp = do_request (session, base_uri, "GET", "/4", NULL,
			  "Test-Set-ETag", "\"abcdefg\"",
			  NULL);
	if (!last_request_validated) {
		debug_printf (1, "    Request for /4 not validated!\n");
		errors++;
	}
	if (last_request_hit_network) {
		debug_printf (1, "    Request for /4 not filled from cache!\n");
		errors++;
	}
	if (strcmp (body4, cmp) != 0) {
		debug_printf (1, "    Cached response (%s) did not match original (%s)\n",
			      cmp, body4);
		errors++;
	}
	g_free (cmp);


	/* Cache-Control: no-cache prevents caching */
	debug_printf (1, "  Uncacheable resource\n");
	cmp = do_request (session, base_uri, "GET", "/5", NULL,
			  "Test-Set-Cache-Control", "no-cache",
			  NULL);
	if (!last_request_hit_network) {
		debug_printf (1, "    Request for /5 filled from cache!\n");
		errors++;
	}
	if (strcmp (body5, cmp) != 0) {
		debug_printf (1, "    Re-retrieved response (%s) did not match original (%s)\n",
			      cmp, body5);
		errors++;
	}
	g_free (cmp);


	/* PUT to a URI invalidates the cache entry */
	debug_printf (1, "  Invalidating and re-requesting a cached resource\n");
	cmp = do_request (session, base_uri, "PUT", "/1", NULL,
			  NULL);
	if (!last_request_hit_network) {
		debug_printf (1, "    PUT filled from cache!\n");
		errors++;
	}
	g_free (cmp);
	cmp = do_request (session, base_uri, "GET", "/1", NULL,
			  NULL);
	if (!last_request_hit_network) {
		debug_printf (1, "    PUT failed to invalidate cache entry!\n");
		errors++;
	}
	g_free (cmp);


	soup_test_session_abort_unref (session);
	g_object_unref (cache);

	g_free (cache_dir);
	g_free (body1);
	g_free (body2);
	g_free (body3);
	g_free (body4);
	g_free (body5);
}

static void
do_cancel_test (SoupURI *base_uri)
{
	SoupSession *session;
	SoupCache *cache;
	char *cache_dir;
	char *body1, *body2;
	guint flags;

	debug_printf (1, "Cache cancel tests\n");

	cache_dir = g_dir_make_tmp ("cache-test-XXXXXX", NULL);
	debug_printf (2, "  Caching to %s\n", cache_dir);
	cache = soup_cache_new (cache_dir, SOUP_CACHE_SINGLE_USER);
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 SOUP_SESSION_ADD_FEATURE, cache,
					 NULL);
	g_signal_connect (session, "request-unqueued",
			  G_CALLBACK (request_unqueued), NULL);

	debug_printf (2, "  Initial requests\n");
	body1 = do_request (session, base_uri, "GET", "/1", NULL,
			    "Test-Set-Expires", "Fri, 01 Jan 2100 00:00:00 GMT",
			    NULL);
	body2 = do_request (session, base_uri, "GET", "/2", NULL,
			    "Test-Set-Last-Modified", "Fri, 01 Jan 2010 00:00:00 GMT",
			    "Test-Set-Cache-Control", "must-revalidate",
			    NULL);

	/* Check that messages are correctly processed on cancellations. */
	debug_printf (1, "  Cancel fresh resource with soup_session_message_cancel()\n");
	flags = SOUP_TEST_REQUEST_CANCEL_MESSAGE | SOUP_TEST_REQUEST_CANCEL_IMMEDIATE;
	do_request_with_cancel (session, base_uri, "GET", "/1", flags);
	if (cancelled_requests != 1) {
		debug_printf (1, "    invalid number of cancelled requests: %d (1 expected)\n",
			      cancelled_requests);
		errors++;
	}

	debug_printf (1, "  Cancel fresh resource with g_cancellable_cancel()\n");
	flags = SOUP_TEST_REQUEST_CANCEL_CANCELLABLE | SOUP_TEST_REQUEST_CANCEL_IMMEDIATE;
	do_request_with_cancel (session, base_uri, "GET", "/1", flags);
	if (cancelled_requests != 1) {
		debug_printf (1, "    invalid number of cancelled requests: %d (1 expected)\n",
			      cancelled_requests);
		errors++;
	}

	soup_test_session_abort_unref (session);

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 SOUP_SESSION_ADD_FEATURE, cache,
					 NULL);
	g_signal_connect (session, "request-unqueued",
			  G_CALLBACK (request_unqueued), NULL);

	/* Check that messages are correctly processed on cancellations. */
	debug_printf (1, "  Cancel a revalidating resource with soup_session_message_cancel()\n");
	flags = SOUP_TEST_REQUEST_CANCEL_MESSAGE | SOUP_TEST_REQUEST_CANCEL_IMMEDIATE;
	do_request_with_cancel (session, base_uri, "GET", "/2", flags);
	if (cancelled_requests != 2) {
		debug_printf (1, "    invalid number of cancelled requests: %d (2 expected)\n",
			      cancelled_requests);
		errors++;
	}

	debug_printf (1, "  Cancel a revalidating resource with g_cancellable_cancel()\n");
	flags = SOUP_TEST_REQUEST_CANCEL_CANCELLABLE | SOUP_TEST_REQUEST_CANCEL_IMMEDIATE;
	do_request_with_cancel (session, base_uri, "GET", "/2", flags);
	if (cancelled_requests != 2) {
		debug_printf (1, "    invalid number of cancelled requests: %d (2 expected)\n",
			      cancelled_requests);
		errors++;
	}

	soup_test_session_abort_unref (session);

	g_object_unref (cache);
	g_free (cache_dir);
	g_free (body1);
	g_free (body2);
}

static gboolean
unref_stream (gpointer stream)
{
	g_object_unref (stream);
	return FALSE;
}

static void
base_stream_unreffed (gpointer loop, GObject *ex_base_stream)
{
	g_main_loop_quit (loop);
}

static void
do_refcounting_test (SoupURI *base_uri)
{
	SoupSession *session;
	SoupCache *cache;
	char *cache_dir;
	SoupRequestHTTP *req;
	GInputStream *stream, *base_stream;
	SoupURI *uri;
	GError *error = NULL;
	guint flags;
	GMainLoop *loop;

	debug_printf (1, "Cache refcounting tests\n");

	cache_dir = g_dir_make_tmp ("cache-test-XXXXXX", NULL);
	debug_printf (2, "  Caching to %s\n", cache_dir);
	cache = soup_cache_new (cache_dir, SOUP_CACHE_SINGLE_USER);
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 SOUP_SESSION_ADD_FEATURE, cache,
					 NULL);

	last_request_validated = last_request_hit_network = FALSE;
	cancelled_requests = 0;

	uri = soup_uri_new_with_base (base_uri, "/1");
	req = soup_session_request_http_uri (session, "GET", uri, NULL);
	soup_uri_free (uri);

	flags = SOUP_TEST_REQUEST_CANCEL_AFTER_SEND_FINISH | SOUP_TEST_REQUEST_CANCEL_MESSAGE;
	stream = soup_test_request_send (SOUP_REQUEST (req), NULL, flags, &error);
	if (!stream) {
		debug_printf (1, "    could not send request: %s\n",
			      error->message);
		g_error_free (error);
		g_object_unref (req);
		return;
	}
	g_object_unref (req);

	base_stream = g_filter_input_stream_get_base_stream (G_FILTER_INPUT_STREAM (stream));

	debug_printf (1, " Checking that the base stream is properly unref'ed\n");
	loop = g_main_loop_new (NULL, FALSE);
	g_object_weak_ref (G_OBJECT (base_stream), base_stream_unreffed, loop);
	g_idle_add (unref_stream, stream);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	soup_cache_flush ((SoupCache *)soup_session_get_feature (session, SOUP_TYPE_CACHE));

	soup_test_session_abort_unref (session);

	g_object_unref (cache);
	g_free (cache_dir);
}

static void
do_headers_test (SoupURI *base_uri)
{
	SoupSession *session;
	SoupMessageHeaders *headers;
	SoupCache *cache;
	char *cache_dir;
	char *body1, *cmp;
	const char *header_value;

	debug_printf (1, "Cache basics\n");

	cache_dir = g_dir_make_tmp ("cache-test-XXXXXX", NULL);
	debug_printf (2, "  Caching to %s\n", cache_dir);
	cache = soup_cache_new (cache_dir, SOUP_CACHE_SINGLE_USER);
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 SOUP_SESSION_ADD_FEATURE, cache,
					 NULL);

	g_signal_connect (session, "request-started",
			  G_CALLBACK (request_started), NULL);

	debug_printf (2, "  Initial requests\n");
	body1 = do_request (session, base_uri, "GET", "/1", NULL,
			    "Test-Set-Last-Modified", "Fri, 01 Jan 2100 00:00:00 GMT",
			    "Test-Set-My-Header", "My header value",
			    NULL);

	/* My-Header new value should be updated in cache */
	debug_printf (2, "  Fresh cached resource which updates My-Header\n");
	cmp = do_request (session, base_uri, "GET", "/1", NULL,
			  "Test-Set-Last-Modified", "Fri, 01 Jan 2010 00:00:00 GMT",
			  "Test-Set-My-Header", "My header NEW value",
			  NULL);
	if (!last_request_validated) {
		debug_printf (1, "    Request for /1 not validated!\n");
		errors++;
	}
	if (last_request_hit_network) {
		debug_printf (1, "    Request for /1 not filled from cache!\n");
		errors++;
	}
	g_free (cmp);

	/* Check that cache returns the updated header */
	debug_printf (2, "  Fresh cached resource with new value for My-Header\n");
	headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_RESPONSE);
	cmp = do_request (session, base_uri, "GET", "/1", headers,
			  "Test-Set-Last-Modified", "Fri, 01 Jan 2010 00:00:00 GMT",
			  NULL);
	if (last_request_hit_network) {
		debug_printf (1, "    Request for /1 not filled from cache!\n");
		errors++;
	}
	g_free (cmp);

	header_value = soup_message_headers_get_list (headers, "My-Header");
	if (!header_value) {
		debug_printf (1, "    Header \"My-Header\" not present!\n");
		errors++;
	} else if (strcmp (header_value, "My header NEW value") != 0) {
		debug_printf (1, "    \"My-Header = %s\" and should be \"%s\"\n",
			      header_value,
			      "My header NEW value");
		errors++;
	}
	soup_message_headers_free (headers);

	soup_test_session_abort_unref (session);
	g_object_unref (cache);

	g_free (cache_dir);
	g_free (body1);
}

int
main (int argc, char **argv)
{
	SoupServer *server;
	SoupURI *base_uri;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_test_server_get_uri (server, "http", NULL);

	do_basics_test (base_uri);
	do_cancel_test (base_uri);
	do_refcounting_test (base_uri);
	do_headers_test (base_uri);

	soup_uri_free (base_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return errors != 0;
}
