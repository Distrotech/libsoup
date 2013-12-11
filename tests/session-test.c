/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

static gboolean server_processed_message;
static gboolean timeout;
static GMainLoop *loop;
static SoupMessagePriority expected_priorities[3];

static gboolean
timeout_cb (gpointer user_data)
{
	gboolean *timeout = user_data;

	*timeout = TRUE;
	return FALSE;
}

static void
server_handler (SoupServer        *server,
		SoupMessage       *msg, 
		const char        *path,
		GHashTable        *query,
		SoupClientContext *client,
		gpointer           user_data)
{
	if (!strcmp (path, "/request-timeout")) {
		GMainContext *context = g_main_context_get_thread_default ();
		GSource *timer;

		timer = g_timeout_source_new (100);
		g_source_set_callback (timer, timeout_cb, &timeout, NULL);
		g_source_attach (timer, context);
		g_source_unref (timer);
	} else
		server_processed_message = TRUE;

	soup_message_set_status (msg, SOUP_STATUS_OK);
	soup_message_set_response (msg, "text/plain",
				   SOUP_MEMORY_STATIC,
				   "ok\r\n", 4);
}

static void
finished_cb (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
	gboolean *finished = user_data;

	*finished = TRUE;
}

static void
cancel_message_cb (SoupMessage *msg, gpointer session)
{
	soup_session_cancel_message (session, msg, SOUP_STATUS_CANCELLED);
	g_main_loop_quit (loop);
}

static void
do_test_for_session (SoupSession *session,
		     SoupURI *uri, SoupURI *timeout_uri,
		     gboolean queue_is_async,
		     gboolean send_is_blocking,
		     gboolean cancel_is_immediate)
{
	SoupMessage *msg;
	gboolean finished, local_timeout;
	guint timeout_id;

	debug_printf (1, "  queue_message\n");
	debug_printf (2, "    requesting timeout\n");
	msg = soup_message_new_from_uri ("GET", timeout_uri);
	soup_session_send_message (session, msg);
	g_object_unref (msg);

	msg = soup_message_new_from_uri ("GET", uri);
	server_processed_message = timeout = finished = FALSE;
	soup_session_queue_message (session, msg, finished_cb, &finished);
	while (!timeout)
		g_usleep (100);
	debug_printf (2, "    got timeout\n");

	if (queue_is_async) {
		if (server_processed_message) {
			debug_printf (1, "    message processed without running main loop!\n");
			errors++;
		}
		debug_printf (2, "    waiting for finished\n");
		while (!finished)
			g_main_context_iteration (NULL, TRUE);
		if (!server_processed_message) {
			debug_printf (1, "    message finished without server seeing it???\n");
			errors++;
		}
	} else {
		if (!server_processed_message) {
			debug_printf (1, "    server failed to immediately receive message!\n");
			errors++;
		}
		debug_printf (2, "    waiting for finished\n");
		if (finished) {
			debug_printf (1, "    message finished without main loop running???\n");
			errors++;
		}
		while (!finished)
			g_main_context_iteration (NULL, TRUE);
	}

	debug_printf (1, "  send_message\n");
	msg = soup_message_new_from_uri ("GET", uri);
	server_processed_message = local_timeout = FALSE;
	timeout_id = g_idle_add_full (G_PRIORITY_HIGH, timeout_cb, &local_timeout, NULL);
	soup_session_send_message (session, msg);

	if (!server_processed_message) {
		debug_printf (1, "    message finished without server seeing it???\n");
		errors++;
	}

	if (send_is_blocking) {
		if (local_timeout) {
			debug_printf (1, "    send_message ran main loop!\n");
			errors++;
		}
	} else {
		if (!local_timeout) {
			debug_printf (1, "    send_message didn't run main loop!\n");
			errors++;
		}
	}

	if (!local_timeout)
		g_source_remove (timeout_id);

	if (!queue_is_async)
		return;

	debug_printf (1, "  cancel_message\n");
	msg = soup_message_new_from_uri ("GET", uri);
	g_object_ref (msg);
	finished = FALSE;
	soup_session_queue_message (session, msg, finished_cb, &finished);
	g_signal_connect (msg, "wrote-headers",
			  G_CALLBACK (cancel_message_cb), session);

	loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (loop);

	if (cancel_is_immediate) {
		if (!finished) {
			debug_printf (1, "    cancel did not finish message!\n");
			errors++;
			debug_printf (2, "    waiting for finished\n");
			while (!finished)
				g_main_context_iteration (NULL, TRUE);
		}
	} else {
		if (finished) {
			debug_printf (1, "    cancel finished message!\n");
			errors++;
		} else {
			while (!finished)
				g_main_context_iteration (NULL, TRUE);
		}
	}

	if (msg->status_code != SOUP_STATUS_CANCELLED) {
		debug_printf (1, "    message finished with status %d %s!\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	g_object_unref (msg);
}

static void
do_plain_tests (SoupURI *uri, SoupURI *timeout_uri)
{
	SoupSession *session;

	debug_printf (1, "SoupSession\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	do_test_for_session (session, uri, timeout_uri, TRUE, TRUE, FALSE);
	soup_test_session_abort_unref (session);
}

static void
do_async_tests (SoupURI *uri, SoupURI *timeout_uri)
{
	SoupSession *session;

	debug_printf (1, "\nSoupSessionAsync\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	do_test_for_session (session, uri, timeout_uri, TRUE, FALSE, TRUE);
	soup_test_session_abort_unref (session);
}

static void
do_sync_tests (SoupURI *uri, SoupURI *timeout_uri)
{
	SoupSession *session;

	debug_printf (1, "\nSoupSessionSync\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	do_test_for_session (session, uri, timeout_uri, FALSE, TRUE, FALSE);
	soup_test_session_abort_unref (session);
}

static void
priority_test_finished_cb (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
	guint *finished_count = user_data;
	SoupMessagePriority priority = soup_message_get_priority (msg);

	if (priority != expected_priorities[*finished_count]) {
		debug_printf (1, "    message %d should have priority %d (%d found)\n",
			      *finished_count, expected_priorities[*finished_count], priority);
		errors++;
	} else
		debug_printf (1, "  received message %d with priority %d\n",
			      *finished_count, priority);

	(*finished_count)++;
}

static void
do_priority_tests (SoupURI *uri)
{
	SoupSession *session;
	int i, finished_count = 0;
	SoupMessagePriority priorities[] =
		{ SOUP_MESSAGE_PRIORITY_LOW,
		  SOUP_MESSAGE_PRIORITY_HIGH,
		  SOUP_MESSAGE_PRIORITY_NORMAL };

	debug_printf (1, "\nSoupSessionAsync\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	g_object_set (session, "max-conns", 1, NULL);

	expected_priorities[0] = SOUP_MESSAGE_PRIORITY_HIGH;
	expected_priorities[1] = SOUP_MESSAGE_PRIORITY_NORMAL;
	expected_priorities[2] = SOUP_MESSAGE_PRIORITY_LOW;

	for (i = 0; i < 3; i++) {
		SoupURI *msg_uri;
		SoupMessage *msg;
		char buf[5];

		g_snprintf (buf, sizeof (buf), "%d", i);
		msg_uri = soup_uri_new_with_base (uri, buf);
		msg = soup_message_new_from_uri ("GET", msg_uri);
		soup_uri_free (msg_uri);

		soup_message_set_priority (msg, priorities[i]);
		soup_session_queue_message (session, msg, priority_test_finished_cb, &finished_count);
	}

	debug_printf (2, "    waiting for finished\n");
	while (finished_count != 3)
		g_main_context_iteration (NULL, TRUE);

	soup_test_session_abort_unref (session);
}

static void
test_session_properties (const char *name,
			 SoupSession *session,
			 GProxyResolver *expected_proxy_resolver,
			 GTlsDatabase *expected_tls_database)
{
	GProxyResolver *proxy_resolver = NULL;
	GTlsDatabase *tlsdb = NULL;

	g_object_get (G_OBJECT (session),
		      SOUP_SESSION_PROXY_RESOLVER, &proxy_resolver,
		      SOUP_SESSION_TLS_DATABASE, &tlsdb,
		      NULL);
	if (proxy_resolver != expected_proxy_resolver) {
		debug_printf (1, "  %s has %s proxy resolver!\n",
			      name, proxy_resolver ? (expected_proxy_resolver ? "wrong" : "a") : "no");
		errors++;
	}
	if (tlsdb != expected_tls_database) {
		debug_printf (1, "  %s has %s TLS database!\n",
			      name, tlsdb ? (expected_tls_database ? "wrong" : "a") : "no");
		errors++;
	}
	g_clear_object (&proxy_resolver);
	g_clear_object (&tlsdb);
}

static void
do_property_tests (void)
{
	SoupSession *session;
	GProxyResolver *proxy_resolver, *default_proxy_resolver;
	GTlsDatabase *tlsdb, *default_tlsdb;
	SoupURI *uri;

	debug_printf (1, "\nTesting session init properties\n");

	default_proxy_resolver = g_proxy_resolver_get_default ();
	default_tlsdb = g_tls_backend_get_default_database (g_tls_backend_get_default ());

	/* NOTE: We intentionally do not use soup_test_session_new() here */

	session = g_object_new (SOUP_TYPE_SESSION,
				NULL);
	test_session_properties ("Base plain session", session,
				 default_proxy_resolver, default_tlsdb);
	g_object_unref (session);

	session = g_object_new (SOUP_TYPE_SESSION,
				SOUP_SESSION_PROXY_RESOLVER, NULL,
				NULL);
	test_session_properties ("Session with NULL :proxy-resolver", session,
				 NULL, default_tlsdb);
	g_object_unref (session);

	proxy_resolver = g_simple_proxy_resolver_new (NULL, NULL);
	session = g_object_new (SOUP_TYPE_SESSION,
				SOUP_SESSION_PROXY_RESOLVER, proxy_resolver,
				NULL);
	test_session_properties ("Session with non-NULL :proxy-resolver", session,
				 proxy_resolver, default_tlsdb);
	g_object_unref (proxy_resolver);
	g_object_unref (session);

	session = g_object_new (SOUP_TYPE_SESSION,
				SOUP_SESSION_PROXY_URI, NULL,
				NULL);
	test_session_properties ("Session with NULL :proxy-uri", session,
				 NULL, default_tlsdb);
	g_object_unref (session);

	uri = soup_uri_new ("http://example.com/");
	session = g_object_new (SOUP_TYPE_SESSION,
				SOUP_SESSION_PROXY_URI, uri,
				NULL);
	g_object_get (G_OBJECT (session),
		      SOUP_SESSION_PROXY_RESOLVER, &proxy_resolver,
		      NULL);
	test_session_properties ("Session with non-NULL :proxy-uri", session,
				 proxy_resolver, default_tlsdb);
	if (!G_IS_SIMPLE_PROXY_RESOLVER (proxy_resolver)) {
		debug_printf (1, "  proxy resolver had wrong type (%s)\n",
			      G_OBJECT_TYPE_NAME (proxy_resolver));
		errors++;
	}
	g_object_unref (proxy_resolver);
	g_object_unref (session);
	soup_uri_free (uri);

	G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
	session = g_object_new (SOUP_TYPE_SESSION,
				SOUP_SESSION_REMOVE_FEATURE_BY_TYPE, SOUP_TYPE_PROXY_URI_RESOLVER,
				NULL);
	test_session_properties ("Session with removed proxy resolver feature", session,
				 NULL, default_tlsdb);
	g_object_unref (session);
	G_GNUC_END_IGNORE_DEPRECATIONS;

	session = g_object_new (SOUP_TYPE_SESSION,
				SOUP_SESSION_TLS_DATABASE, NULL,
				NULL);
	test_session_properties ("Session with NULL :tls-database", session,
				 default_proxy_resolver, NULL);
	g_object_unref (session);

	/* g_tls_file_database_new() will fail with the dummy backend,
	 * so we can only do this test if we have a real TLS backend.
	 */
	if (tls_available) {
		tlsdb = g_tls_file_database_new (SRCDIR "/test-cert.pem", NULL);
		session = g_object_new (SOUP_TYPE_SESSION,
					SOUP_SESSION_TLS_DATABASE, tlsdb,
					NULL);
		test_session_properties ("Session with non-NULL :tls-database", session,
					 default_proxy_resolver, tlsdb);
		g_object_unref (tlsdb);
		g_object_unref (session);
	}

	session = g_object_new (SOUP_TYPE_SESSION,
				SOUP_SESSION_SSL_USE_SYSTEM_CA_FILE, FALSE,
				NULL);
	test_session_properties ("Session with :ssl-use-system-ca-file FALSE", session,
				 default_proxy_resolver, NULL);
	g_object_unref (session);

	session = g_object_new (SOUP_TYPE_SESSION,
				SOUP_SESSION_SSL_USE_SYSTEM_CA_FILE, TRUE,
				NULL);
	test_session_properties ("Session with :ssl-use-system-ca-file TRUE", session,
				 default_proxy_resolver, default_tlsdb);
	g_object_unref (session);
}

int
main (int argc, char **argv)
{
	SoupServer *server;
	SoupURI *uri, *timeout_uri;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
	uri = soup_test_server_get_uri (server, "http", NULL);
	timeout_uri = soup_uri_new_with_base (uri, "/request-timeout");

	do_plain_tests (uri, timeout_uri);
	do_async_tests (uri, timeout_uri);
	do_sync_tests (uri, timeout_uri);
	do_priority_tests (uri);
	do_property_tests ();

	soup_uri_free (uri);
	soup_uri_free (timeout_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return errors != 0;
}
