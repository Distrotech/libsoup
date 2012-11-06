/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

#include <glib/gprintf.h>

#include <locale.h>
#include <signal.h>

#ifdef HAVE_APACHE
static gboolean apache_running;
#endif

static SoupLogger *logger;

int debug_level, errors;
gboolean parallelize = TRUE;
gboolean expect_warning, tls_available;
static int http_debug_level;

static gboolean
increment_debug_level (const char *option_name, const char *value,
		       gpointer data, GError **error)
{
	debug_level++;
	return TRUE;
}

static gboolean
increment_http_debug_level (const char *option_name, const char *value,
			    gpointer data, GError **error)
{
	http_debug_level++;
	return TRUE;
}

static GOptionEntry debug_entry[] = {
	{ "debug", 'd', G_OPTION_FLAG_NO_ARG,
	  G_OPTION_ARG_CALLBACK, increment_debug_level,
	  "Enable (or increase) test-specific debugging", NULL },
	{ "parallel", 'p', G_OPTION_FLAG_REVERSE,
	  G_OPTION_ARG_NONE, &parallelize,
	  "Toggle parallelization (default is on, unless -d or -h)", NULL },
	{ "http-debug", 'h', G_OPTION_FLAG_NO_ARG,
	  G_OPTION_ARG_CALLBACK, increment_http_debug_level,
	  "Enable (or increase) HTTP-level debugging", NULL },
	{ NULL }
};

static void
quit (int sig)
{
#ifdef HAVE_APACHE
	if (apache_running)
		apache_cleanup ();
#endif

	exit (1);
}

static void
test_log_handler (const char *log_domain, GLogLevelFlags log_level,
		  const char *message, gpointer user_data)
{
	if (log_level & (G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL)) {
		if (expect_warning) {
			expect_warning = FALSE;
			debug_printf (2, "Got expected warning: %s\n", message);
			return;
		} else
			errors++;
	}
	g_log_default_handler (log_domain, log_level, message, user_data);
}

void
test_init (int argc, char **argv, GOptionEntry *entries)
{
	GOptionContext *opts;
	char *name;
	GError *error = NULL;
	GTlsBackend *tls_backend;

	setlocale (LC_ALL, "");
	g_setenv ("GSETTINGS_BACKEND", "memory", TRUE);

	name = strrchr (argv[0], '/');
	if (!name++)
		name = argv[0];
	if (!strncmp (name, "lt-", 3))
		name += 3;
	g_set_prgname (name);

	opts = g_option_context_new (NULL);
	g_option_context_add_main_entries (opts, debug_entry, NULL);
	if (entries)
		g_option_context_add_main_entries (opts, entries, NULL);

	if (!g_option_context_parse (opts, &argc, &argv, &error)) {
		g_printerr ("Could not parse arguments: %s\n",
			    error->message);
		g_printerr ("%s",
			    g_option_context_get_help (opts, TRUE, NULL));
		exit (1);
	}
	g_option_context_free (opts);

	if (debug_level > 0 || http_debug_level > 0)
		parallelize = !parallelize;

	if (g_getenv ("SOUP_TESTS_IN_MAKE_CHECK"))
		debug_level = G_MAXINT;

	/* Exit cleanly on ^C in case we're valgrinding. */
	signal (SIGINT, quit);

	g_log_set_default_handler (test_log_handler, NULL);

	tls_backend = g_tls_backend_get_default ();
	tls_available = g_tls_backend_supports_tls (tls_backend);
}

void
test_cleanup (void)
{
#ifdef HAVE_APACHE
	if (apache_running)
		apache_cleanup ();
#endif

	if (logger)
		g_object_unref (logger);

	g_main_context_unref (g_main_context_default ());

	debug_printf (1, "\n");
	if (errors) {
		g_print ("%s: %d error(s).%s\n",
			 g_get_prgname (), errors,
			 debug_level == 0 ? " Run with '-d' for details" : "");
	} else
		g_print ("%s: OK\n", g_get_prgname ());
}

void
debug_printf (int level, const char *format, ...)
{
	va_list args;

	if (debug_level < level)
		return;

	va_start (args, format);
	g_vprintf (format, args);
	va_end (args);
}

#ifdef HAVE_APACHE

static gboolean
apache_cmd (const char *cmd)
{
	const char *argv[8];
	char *cwd, *conf;
	int status;
	gboolean ok;

	cwd = g_get_current_dir ();
	conf = g_build_filename (cwd, "httpd.conf", NULL);

	argv[0] = APACHE_HTTPD;
	argv[1] = "-d";
	argv[2] = cwd;
	argv[3] = "-f";
	argv[4] = conf;
	argv[5] = "-k";
	argv[6] = cmd;
	argv[7] = NULL;

	ok = g_spawn_sync (cwd, (char **)argv, NULL, 0, NULL, NULL,
			   NULL, NULL, &status, NULL);
	if (ok)
		ok = (status == 0);

	g_free (cwd);
	g_free (conf);

	return ok;
}

void
apache_init (void)
{
	if (g_getenv ("SOUP_TESTS_IN_MAKE_CHECK"))
		return;

	if (!apache_cmd ("start")) {
		g_printerr ("Could not start apache\n");
		exit (1);
	}
	apache_running = TRUE;
}

void
apache_cleanup (void)
{
	pid_t pid;
	char *contents;

	if (g_file_get_contents ("httpd.pid", &contents, NULL, NULL)) {
		pid = strtoul (contents, NULL, 10);
		g_free (contents);
	} else
		pid = 0;

	if (!apache_cmd ("graceful-stop"))
		return;
	apache_running = FALSE;

	if (pid) {
		while (kill (pid, 0) == 0)
			g_usleep (100);
	}
}

#endif /* HAVE_APACHE */

SoupSession *
soup_test_session_new (GType type, ...)
{
	va_list args;
	const char *propname;
	SoupSession *session;

	va_start (args, type);
	propname = va_arg (args, const char *);
	session = (SoupSession *)g_object_new_valist (type, propname, args);
	va_end (args);

	g_object_set (G_OBJECT (session),
		      SOUP_SESSION_SSL_CA_FILE, SRCDIR "/test-cert.pem",
		      NULL);

	if (http_debug_level && !logger) {
		SoupLoggerLogLevel level = MIN ((SoupLoggerLogLevel)http_debug_level, SOUP_LOGGER_LOG_BODY);

		logger = soup_logger_new (level, -1);
	}

	if (logger)
		soup_session_add_feature (session, SOUP_SESSION_FEATURE (logger));

	return session;
}

void
soup_test_session_abort_unref (SoupSession *session)
{
	g_object_add_weak_pointer (G_OBJECT (session), (gpointer *)&session);

	soup_session_abort (session);
	g_object_unref (session);

	if (session) {
		errors++;
		debug_printf (1, "leaked SoupSession!\n");
		g_object_remove_weak_pointer (G_OBJECT (session), (gpointer *)&session);
	}
}

static void
server_listen (SoupServer *server)
{
	GError *error = NULL;
	SoupServerListenOptions options =
		GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (server), "listen-options"));

	soup_server_listen_local (server, 0, options, &error);
	if (error) {
		g_printerr ("Unable to create server: %s\n", error->message);
		exit (1);
	}
}

static GMutex server_start_mutex;
static GCond server_start_cond;

static gpointer
run_server_thread (gpointer user_data)
{
	SoupServer *server = user_data;
	GMainContext *context;
	GMainLoop *loop;

	context = g_main_context_new ();
	g_main_context_push_thread_default (context);
	loop = g_main_loop_new (context, FALSE);
	g_object_set_data (G_OBJECT (server), "GMainLoop", loop);

	server_listen (server);

	g_mutex_lock (&server_start_mutex);
	g_cond_signal (&server_start_cond);
	g_mutex_unlock (&server_start_mutex);

	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	soup_server_disconnect (server);

	g_main_context_pop_thread_default (context);
	g_main_context_unref (context);

	return NULL;
}

SoupServer *
soup_test_server_new (SoupTestServerOptions options)
{
	SoupServer *server;
	GTlsCertificate *cert = NULL;
	GError *error = NULL;

	if (tls_available) {
		cert = g_tls_certificate_new_from_files (SRCDIR "/test-cert.pem",
							 SRCDIR "/test-key.pem",
							 &error);
		if (error) {
			g_printerr ("Unable to create server: %s\n", error->message);
			exit (1);
		}
	}
	
	server = soup_server_new (SOUP_SERVER_TLS_CERTIFICATE, cert,
				  NULL);
	g_clear_object (&cert);

	g_object_set_data (G_OBJECT (server), "options", GUINT_TO_POINTER (options));

	if (options & SOUP_TEST_SERVER_IN_THREAD) {
		GThread *thread;

		g_mutex_lock (&server_start_mutex);

		thread = g_thread_new ("server_thread", run_server_thread, server);
		g_object_set_data (G_OBJECT (server), "thread", thread);

		/* We have to call soup_server_listen() from the server's
		 * thread, but want to be sure we don't return from here
		 * until it happens, hence the locking.
		 */
		g_cond_wait (&server_start_cond, &server_start_mutex);
		g_mutex_unlock (&server_start_mutex);
	} else
		server_listen (server);

	return server;
}

static SoupURI *
find_server_uri (SoupServer *server, const char *scheme, const char *host)
{
	GSList *uris, *u;
	SoupURI *uri, *ret_uri = NULL;

	uris = soup_server_get_uris (server);
	for (u = uris; u; u = u->next) {
		uri = u->data;

		if (scheme && strcmp (uri->scheme, scheme) != 0)
			continue;
		if (host && strcmp (uri->host, host) != 0)
			continue;

		ret_uri = soup_uri_copy (uri);
		break;
	}
	g_slist_free_full (uris, (GDestroyNotify)soup_uri_free);

	return ret_uri;
}

static SoupURI *
add_listener (SoupServer *server, const char *scheme, const char *host)
{
	SoupServerListenOptions options = 0;
	GError *error = NULL;

	if (!g_strcmp0 (scheme, SOUP_URI_SCHEME_HTTPS))
		options |= SOUP_SERVER_LISTEN_HTTPS;
	if (!g_strcmp0 (host, "127.0.0.1"))
		options |= SOUP_SERVER_LISTEN_IPV4_ONLY;
	else if (!g_strcmp0 (host, "::1"))
		options |= SOUP_SERVER_LISTEN_IPV6_ONLY;

	soup_server_listen_local (server, 0, options, &error);
	g_assert_no_error (error);

	return find_server_uri (server, scheme, host);
}

typedef struct {
	GMutex mutex;
	GCond cond;

	SoupServer *server;
	const char *scheme;
	const char *host;

	SoupURI *uri;
} AddListenerData;

static gboolean
add_listener_in_thread (gpointer user_data)
{
	AddListenerData *data = user_data;

	data->uri = add_listener (data->server, data->scheme, data->host);
	g_mutex_lock (&data->mutex);
	g_cond_signal (&data->cond);
	g_mutex_unlock (&data->mutex);

	return FALSE;
}

SoupURI *
soup_test_server_get_uri (SoupServer    *server,
			  const char    *scheme,
			  const char    *host)
{
	SoupURI *uri;
	GMainLoop *loop;

	uri = find_server_uri (server, scheme, host);
	if (uri)
		return uri;

	/* Need to add a new listener */
	uri = soup_uri_new (NULL);
	soup_uri_set_scheme (uri, scheme);
	soup_uri_set_host (uri, host);

	loop = g_object_get_data (G_OBJECT (server), "GMainLoop");
	if (loop) {
		GMainContext *context = g_main_loop_get_context (loop);
		AddListenerData data;

		g_mutex_init (&data.mutex);
		g_cond_init (&data.cond);
		data.server = server;
		data.scheme = scheme;
		data.host = host;
		data.uri = NULL;

		g_mutex_lock (&data.mutex);
		soup_add_completion (context, add_listener_in_thread, &data);

		while (!data.uri)
			g_cond_wait (&data.cond, &data.mutex);

		g_mutex_clear (&data.mutex);
		g_cond_clear (&data.cond);
		uri = data.uri;
	} else
		uri = add_listener (server, scheme, host);

	return uri;
}

static gboolean
idle_quit_server (gpointer loop)
{
	g_main_loop_quit (loop);
	return FALSE;
}

void
soup_test_server_quit_unref (SoupServer *server)
{
	GThread *thread;

	g_object_add_weak_pointer (G_OBJECT (server),
				   (gpointer *)&server);

	thread = g_object_get_data (G_OBJECT (server), "thread");
	if (thread) {
		GMainLoop *loop;
		GMainContext *context;

		loop = g_object_get_data (G_OBJECT (server), "GMainLoop");
		context = g_main_loop_get_context (loop);
		soup_add_completion (context, idle_quit_server, loop);
		g_thread_join (thread);
	} else
		soup_server_disconnect (server);
	g_object_unref (server);

	if (server) {
		errors++;
		debug_printf (1, "leaked SoupServer!\n");
		g_object_remove_weak_pointer (G_OBJECT (server),
					      (gpointer *)&server);
	}
}

typedef struct {
	GMainLoop *loop;
	GAsyncResult *result;
} AsyncAsSyncData;

static void
async_as_sync_callback (GObject      *object,
			GAsyncResult *result,
			gpointer      user_data)
{
	AsyncAsSyncData *data = user_data;
	GMainContext *context;

	data->result = g_object_ref (result);
	context = g_main_loop_get_context (data->loop);
	while (g_main_context_pending (context))
		g_main_context_iteration (context, FALSE);
	g_main_loop_quit (data->loop);
}

typedef struct {
	SoupRequest  *req;
	GCancellable *cancellable;
	SoupTestRequestFlags flags;
} CancelData;

static CancelData *
create_cancel_data (SoupRequest          *req,
		    GCancellable         *cancellable,
		    SoupTestRequestFlags  flags)
{
	CancelData *cancel_data;

	if (!flags)
		return NULL;

	cancel_data = g_slice_new0 (CancelData);
	cancel_data->flags = flags;
	if (flags & SOUP_TEST_REQUEST_CANCEL_MESSAGE && SOUP_IS_REQUEST_HTTP (req))
		cancel_data->req = g_object_ref (req);
	else if (flags & SOUP_TEST_REQUEST_CANCEL_CANCELLABLE)
		cancel_data->cancellable = g_object_ref (cancellable);
	return cancel_data;
}

static void inline
cancel_message_or_cancellable (CancelData *cancel_data)
{
	if (cancel_data->flags & SOUP_TEST_REQUEST_CANCEL_MESSAGE) {
		SoupRequest *req = cancel_data->req;
		SoupMessage *msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (req));
		soup_session_cancel_message (soup_request_get_session (req), msg,
					     SOUP_STATUS_CANCELLED);
		g_object_unref (msg);
		g_object_unref (req);
	} else if (cancel_data->flags & SOUP_TEST_REQUEST_CANCEL_CANCELLABLE) {
		g_cancellable_cancel (cancel_data->cancellable);
		g_object_unref (cancel_data->cancellable);
	}
	g_slice_free (CancelData, cancel_data);
}

static gboolean
cancel_request_timeout (gpointer data)
{
	cancel_message_or_cancellable ((CancelData *) data);
	return FALSE;
}

static gpointer
cancel_request_thread (gpointer data)
{
	g_usleep (100000); /* .1s */
	cancel_message_or_cancellable ((CancelData *) data);
	return NULL;
}

GInputStream *
soup_test_request_send (SoupRequest   *req,
			GCancellable  *cancellable,
			guint          flags,
			GError       **error)
{
	AsyncAsSyncData data;
	GInputStream *stream;
	CancelData *cancel_data = create_cancel_data (req, cancellable, flags);

	if (SOUP_IS_SESSION_SYNC (soup_request_get_session (req))) {
		GThread *thread;

		if (cancel_data)
			thread = g_thread_new ("cancel_request_thread", cancel_request_thread,
					       cancel_data);
		stream = soup_request_send (req, cancellable, error);
		if (cancel_data)
			g_thread_unref (thread);
		return stream;
	}

	data.loop = g_main_loop_new (g_main_context_get_thread_default (), FALSE);
	if (cancel_data &&
	    (flags & SOUP_TEST_REQUEST_CANCEL_SOON || flags & SOUP_TEST_REQUEST_CANCEL_IMMEDIATE)) {
		guint interval = flags & SOUP_TEST_REQUEST_CANCEL_SOON ? 100 : 0;
		g_timeout_add_full (G_PRIORITY_HIGH, interval, cancel_request_timeout, cancel_data, NULL);
	}
	if (cancel_data && (flags & SOUP_TEST_REQUEST_CANCEL_PREEMPTIVE))
		g_cancellable_cancel (cancellable);
	soup_request_send_async (req, cancellable, async_as_sync_callback, &data);
	g_main_loop_run (data.loop);

	stream = soup_request_send_finish (req, data.result, error);

	if (cancel_data && (flags &  SOUP_TEST_REQUEST_CANCEL_AFTER_SEND_FINISH)) {
		GMainContext *context;

		cancel_message_or_cancellable (cancel_data);

		context = g_main_loop_get_context (data.loop);
		while (g_main_context_pending (context))
			g_main_context_iteration (context, FALSE);
	}

	g_main_loop_unref (data.loop);
	g_object_unref (data.result);

	return stream;
}

gboolean
soup_test_request_read_all (SoupRequest   *req,
			    GInputStream  *stream,
			    GCancellable  *cancellable,
			    GError       **error)
{
	char buf[8192];
	AsyncAsSyncData data;
	gsize nread;

	if (!SOUP_IS_SESSION_SYNC (soup_request_get_session (req)))
		data.loop = g_main_loop_new (g_main_context_get_thread_default (), FALSE);

	do {
		if (SOUP_IS_SESSION_SYNC (soup_request_get_session (req))) {
			nread = g_input_stream_read (stream, buf, sizeof (buf),
						     cancellable, error);
		} else {
			g_input_stream_read_async (stream, buf, sizeof (buf),
						   G_PRIORITY_DEFAULT, cancellable,
						   async_as_sync_callback, &data);
			g_main_loop_run (data.loop);
			nread = g_input_stream_read_finish (stream, data.result, error);
			g_object_unref (data.result);
		}
	} while (nread > 0);

	if (!SOUP_IS_SESSION_SYNC (soup_request_get_session (req)))
		g_main_loop_unref (data.loop);

	return nread == 0;
}

gboolean
soup_test_request_close_stream (SoupRequest   *req,
				GInputStream  *stream,
				GCancellable  *cancellable,
				GError       **error)
{
	AsyncAsSyncData data;
	gboolean ok;

	if (SOUP_IS_SESSION_SYNC (soup_request_get_session (req)))
		return g_input_stream_close (stream, cancellable, error);

	data.loop = g_main_loop_new (g_main_context_get_thread_default (), FALSE);

	g_input_stream_close_async (stream, G_PRIORITY_DEFAULT, cancellable,
				    async_as_sync_callback, &data);
	g_main_loop_run (data.loop);

	ok = g_input_stream_close_finish (stream, data.result, error);

	g_main_loop_unref (data.loop);
	g_object_unref (data.result);

	return ok;
}
