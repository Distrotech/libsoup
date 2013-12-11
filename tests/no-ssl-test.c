/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

static void
do_ssl_test_for_session (SoupSession *session, const char *uri)
{
	SoupMessage *msg;
	GTlsCertificate *cert = NULL;
	GTlsCertificateFlags flags;
	gboolean is_https;

	msg = soup_message_new ("GET", uri);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_SSL_FAILED);

	is_https = soup_message_get_https_status (msg, &cert, &flags);
	soup_test_assert (!is_https, "get_http_status() returned TRUE? (flags %x)", flags);

	g_assert_null (cert);
	g_assert_false (soup_message_get_flags (msg) & SOUP_MESSAGE_CERTIFICATE_TRUSTED);

	g_object_unref (msg);
}

static void
do_ssl_tests (gconstpointer uri)
{
	SoupSession *session;

	debug_printf (1, "\nSoupSession without SSL support\n");

	debug_printf (1, "  plain\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	do_ssl_test_for_session (session, uri);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  async\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	do_ssl_test_for_session (session, uri);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  sync\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	do_ssl_test_for_session (session, uri);
	soup_test_session_abort_unref (session);
}

static void
do_session_property_tests (void)
{
	gboolean use_system;
	GTlsDatabase *tlsdb;
	char *ca_file;
	SoupSession *session;

	debug_printf (1, "session properties\n");

	session = soup_session_async_new ();

	g_object_get (G_OBJECT (session),
		      "ssl-use-system-ca-file", &use_system,
		      "tls-database", &tlsdb,
		      "ssl-ca-file", &ca_file,
		      NULL);
	soup_test_assert (!use_system, "ssl-use-system-ca-file defaults to TRUE");
	soup_test_assert (tlsdb == NULL, "tls-database set by default");
	soup_test_assert (ca_file == NULL, "ca-file set by default");

	g_object_set (G_OBJECT (session),
		      "ssl-use-system-ca-file", TRUE,
		      NULL);
	g_object_get (G_OBJECT (session),
		      "ssl-ca-file", &ca_file,
		      NULL);
	soup_test_assert (ca_file == NULL, "setting ssl-use-system-ca-file set ssl-ca-file");

	g_object_set (G_OBJECT (session),
		      "ssl-ca-file",
		      g_test_get_filename (G_TEST_DIST, "test-cert.pem", NULL),
		      NULL);
	g_object_get (G_OBJECT (session),
		      "ssl-use-system-ca-file", &use_system,
		      "tls-database", &tlsdb,
		      "ssl-ca-file", &ca_file,
		      NULL);
	soup_test_assert (ca_file == NULL, "setting ssl-ca-file did not fail");
	soup_test_assert (!use_system, "setting ssl-ca-file set ssl-use-system-ca-file");
	soup_test_assert (tlsdb == NULL, "setting ssl-ca-file set tls-database");

	g_object_set (G_OBJECT (session),
		      "tls-database", NULL,
		      NULL);
	g_object_get (G_OBJECT (session),
		      "ssl-use-system-ca-file", &use_system,
		      "tls-database", &tlsdb,
		      "ssl-ca-file", &ca_file,
		      NULL);
	soup_test_assert (tlsdb == NULL, "setting tls-database NULL failed");
	soup_test_assert (!use_system, "setting tls-database NULL set ssl-use-system-ca-file");
	soup_test_assert (ca_file == NULL, "setting tls-database NULL set ssl-ca-file");

	soup_test_session_abort_unref (session);
}

static void
server_handler (SoupServer        *server,
		SoupMessage       *msg, 
		const char        *path,
		GHashTable        *query,
		SoupClientContext *client,
		gpointer           user_data)
{
	soup_message_set_status (msg, SOUP_STATUS_OK);
	soup_message_set_response (msg, "text/plain",
				   SOUP_MEMORY_STATIC,
				   "ok\r\n", 4);
}

int
main (int argc, char **argv)
{
	SoupServer *server;
	char *uri;
	int ret;

	/* Force this test to use the dummy TLS backend */
	g_setenv ("GIO_USE_TLS", "dummy", TRUE);

	test_init (argc, argv, NULL);

	/* Make a non-SSL server and pretend that it's ssl, which is fine
	 * since we won't ever actually talk to it anyway. We don't
	 * currently test that failing to construct an SSL server works.
	 */
	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
	uri = g_strdup_printf ("https://127.0.0.1:%u/",
			       soup_server_get_port (server));

	g_test_add_func ("/no-ssl/session-properties", do_session_property_tests);
	g_test_add_data_func ("/no-ssl/request-error", uri, do_ssl_tests);

	ret = g_test_run ();

	g_free (uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
