/* -*- Mode: C; tabstop: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-auth-negotiate.c: HTTP Negotiate Authentication helper
 *
 * Copyright (C) 2009,2013 Guido Guenther <agx@sigxcpu.org>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_GSSAPI
# include <gssapi/gssapi.h>
#endif

#include <string.h>

#include "soup-auth-negotiate.h"
#include "soup-gssapi.h"
#include "soup-headers.h"
#include "soup-message.h"
#include "soup-message-private.h"
#include "soup-misc.h"
#include "soup-uri.h"

static gboolean soup_gss_build_response (SoupNegotiateConnectionState *conn,
					 SoupAuth *auth, GError **err);
static gchar** parse_trusted_uris (void);
static gboolean check_auth_trusted_uri (SoupAuthNegotiate *negotiate,
					SoupMessage *msg);

typedef struct {
	char *username;
} SoupAuthNegotiatePrivate;
#define SOUP_AUTH_NEGOTIATE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_AUTH_NEGOTIATE, SoupAuthNegotiatePrivate))

G_DEFINE_TYPE (SoupAuthNegotiate, soup_auth_negotiate, SOUP_TYPE_CONNECTION_AUTH)

/* Function pointers to dlopen'ed libsoup-gssapi */
struct {
	int (*client_init)(SoupNegotiateConnectionState *conn,
			   const char *host,
			   GError **err);
	int (*client_step)(SoupNegotiateConnectionState *conn,
			   const char *challenge,
			   GError **err);
	void (*client_cleanup)(SoupNegotiateConnectionState *conn);
} soup_gssapi_syms;
gboolean have_gssapi;

static gchar **trusted_uris;

static void
soup_auth_negotiate_init (SoupAuthNegotiate *negotiate)
{
}

static void
soup_auth_negotiate_finalize (GObject *object)
{
	SoupAuthNegotiatePrivate *priv = SOUP_AUTH_NEGOTIATE_GET_PRIVATE (object);

	g_free (priv->username);

	G_OBJECT_CLASS (soup_auth_negotiate_parent_class)->finalize (object);
}

static gpointer
soup_auth_negotiate_create_connection_state (SoupConnectionAuth *auth)
{
	return g_slice_new0 (SoupNegotiateConnectionState);
}

static void
soup_auth_negotiate_free_connection_state (SoupConnectionAuth *auth,
					   gpointer state)
{
	SoupNegotiateConnectionState *conn = state;

	if (have_gssapi)
		soup_gssapi_syms.client_cleanup (conn);
	g_free (conn->response_header);
}

static gboolean
soup_auth_negotiate_update_connection (SoupConnectionAuth *auth, SoupMessage *msg,
				       const char *header, gpointer state)
{
	SoupAuthNegotiatePrivate *priv =
		SOUP_AUTH_NEGOTIATE_GET_PRIVATE (auth);
	SoupNegotiateConnectionState *conn = state;
	GError *err = NULL;

	if (conn->state > SOUP_NEGOTIATE_RECEIVED_CHALLENGE) {
		/* We already authenticated, but then got another 401.
		 * That means "permission denied", so don't try to
		 * authenticate again.
		 */
		conn->state = SOUP_NEGOTIATE_FAILED;

		/* Make sure we don't claim to be authenticated */
		g_free (priv->username);
		priv->username = NULL;

		return FALSE;
	}

	/* Found negotiate header, start negotiate */
	if (strcmp (header, "Negotiate") == 0) {
		conn->state = SOUP_NEGOTIATE_RECEIVED_CHALLENGE;
		if (soup_gss_build_response (conn, SOUP_AUTH (auth), &err))
			return TRUE;
		else {
			/* FIXME: report further upward via
			 * soup_message_get_error_message  */
			g_warning ("gssapi step failed: %s", err->message);
		}
	}
	g_clear_error (&err);
	return FALSE;
}

static GSList *
soup_auth_negotiate_get_protection_space (SoupAuth *auth, SoupURI *source_uri)
{
	char *space, *p;

	space = g_strdup (source_uri->path);

	/* Strip filename component */
	p = strrchr (space, '/');
	if (p && p != space && p[1])
		*p = '\0';

	return g_slist_prepend (NULL, space);
}

static void
soup_auth_negotiate_authenticate (SoupAuth *auth, const char *username,
				  const char *password)
{
	SoupAuthNegotiatePrivate *priv = SOUP_AUTH_NEGOTIATE_GET_PRIVATE (auth);

	g_return_if_fail (username != NULL);
	priv->username = g_strdup (username);
}

static gboolean
soup_auth_negotiate_is_authenticated (SoupAuth *auth)
{
	return SOUP_AUTH_NEGOTIATE_GET_PRIVATE (auth)->username != NULL;
}

static gboolean
soup_auth_negotiate_is_ready (SoupAuth *auth,
			      SoupMessage *msg)
{
	SoupAuthNegotiate* negotiate = SOUP_AUTH_NEGOTIATE (auth);
	return check_auth_trusted_uri (negotiate, msg);
}

static void
check_server_response(SoupMessage *msg, gpointer state)
{
	gint ret;
	const char *auth_headers;
	SoupNegotiateConnectionState *conn = state;
	GError *err = NULL;

	if (msg->status_code == SOUP_STATUS_UNAUTHORIZED)
		return;

	/* FIXME: need to check for proxy-auth too */
	auth_headers = soup_message_headers_get_one (msg->response_headers,
						     "WWW-Authenticate");
	if (!auth_headers || g_ascii_strncasecmp (auth_headers, "Negotiate ", 10) != 0) {
		g_warning ("Failed to parse auth header %s", auth_headers);
		conn->state = SOUP_NEGOTIATE_FAILED;
		goto out;
	}

	ret = soup_gssapi_syms.client_step (conn, auth_headers + 10, &err);

	if (ret != AUTH_GSS_COMPLETE) {
		g_warning ("%s", err->message);
		conn->state = SOUP_NEGOTIATE_FAILED;
	}
 out:
	g_clear_error (&err);
}

static void
remove_server_response_handler(SoupMessage *msg, gpointer state)
{
	g_signal_handlers_disconnect_by_func (msg,
					      G_CALLBACK (check_server_response),
					      state);
}


static char *
soup_auth_negotiate_get_connection_authorization (SoupConnectionAuth *auth,
						  SoupMessage *msg,
						  gpointer state)
{
	SoupNegotiateConnectionState *conn = state;
	char *header = NULL;

	if (conn->state == SOUP_NEGOTIATE_RECEIVED_CHALLENGE) {
		header = conn->response_header;
		conn->response_header = NULL;
		conn->state = SOUP_NEGOTIATE_SENT_RESPONSE;
	}

	g_signal_connect (msg,
			  "finished",
			  G_CALLBACK (remove_server_response_handler),
			  conn);

	/* Wait for the 2xx response to verify server response */
	g_signal_connect (msg,
			  "got_headers",
			  G_CALLBACK (check_server_response),
			  conn);

	return header;
}

static gboolean
soup_auth_negotiate_is_connection_ready (SoupConnectionAuth *auth,
					 SoupMessage        *msg,
					 gpointer            state)
{
	SoupNegotiateConnectionState *conn = state;

	return conn->state != SOUP_NEGOTIATE_FAILED;
}

static gboolean
soup_gssapi_load (void)
{
	GModule *gssapi;
	const char *modulename = PACKAGE "-gssapi-2.4." G_MODULE_SUFFIX;

	if (!g_module_supported ())
		return FALSE;

	gssapi = g_module_open (modulename, G_MODULE_BIND_LOCAL);
	if (!gssapi) {
		g_warning ("Failed to load %s - negotiate support will "
			   "be disabled.", modulename);
		return FALSE;
	}

#define GSSAPI_BIND_SYMBOL(name) \
	g_return_val_if_fail (g_module_symbol (gssapi, "soup_gss_" #name, (gpointer)&soup_gssapi_syms.name), FALSE)

	GSSAPI_BIND_SYMBOL(client_step);
	GSSAPI_BIND_SYMBOL(client_init);
	GSSAPI_BIND_SYMBOL(client_cleanup);
#undef GSSPI_BIND_SYMBOL
	return TRUE;
}

static void
soup_auth_negotiate_class_init (SoupAuthNegotiateClass *auth_negotiate_class)
{
	SoupAuthClass *auth_class = SOUP_AUTH_CLASS (auth_negotiate_class);
	SoupConnectionAuthClass *conn_auth_class =
			SOUP_CONNECTION_AUTH_CLASS (auth_negotiate_class);
	GObjectClass *object_class = G_OBJECT_CLASS (auth_negotiate_class);

	g_type_class_add_private (auth_negotiate_class, sizeof (SoupAuthNegotiatePrivate));

	auth_class->scheme_name = "Negotiate";
	auth_class->strength = 7;

	auth_class->get_protection_space = soup_auth_negotiate_get_protection_space;
	auth_class->authenticate = soup_auth_negotiate_authenticate;
	auth_class->is_authenticated = soup_auth_negotiate_is_authenticated;
	auth_class->is_ready = soup_auth_negotiate_is_ready;

	conn_auth_class->create_connection_state = soup_auth_negotiate_create_connection_state;
	conn_auth_class->free_connection_state = soup_auth_negotiate_free_connection_state;
	conn_auth_class->update_connection = soup_auth_negotiate_update_connection;
	conn_auth_class->get_connection_authorization = soup_auth_negotiate_get_connection_authorization;
	conn_auth_class->is_connection_ready = soup_auth_negotiate_is_connection_ready;

	object_class->finalize = soup_auth_negotiate_finalize;

	trusted_uris = parse_trusted_uris ();
	have_gssapi = soup_gssapi_load();
}

static gboolean
soup_gss_build_response (SoupNegotiateConnectionState *conn, SoupAuth *auth, GError **err)
{
	if (!have_gssapi) {
		if (err && *err == NULL) {
			g_set_error (err,
				     SOUP_HTTP_ERROR,
				     SOUP_STATUS_GSSAPI_FAILED,
				     "GSSAPI unavailable");
		}
		return FALSE;
	}

	if (!soup_gssapi_syms.client_init (conn, soup_auth_get_host (SOUP_AUTH (auth)), err))
		return FALSE;

	if (soup_gssapi_syms.client_step (conn, "", err) != AUTH_GSS_CONTINUE)
		return FALSE;

	return TRUE;
}

/* Parses a comma separated list of URIS from the environment. */
static gchar**
parse_trusted_uris(void)
{
	gchar **uris = NULL;
	const gchar *env;

	env = g_getenv ("SOUP_AUTH_TRUSTED_URIS");
	if (env)
		uris = g_strsplit (env, ",", -1);
	return uris;
}

/* check if scheme://host:port from msg matches the trusted uri */
static gboolean
match_base_uri (SoupMessage *msg, const gchar *trusted)
{
	SoupURI *uri;
	gboolean ret = FALSE;

	/* params of the trusted uri */
	gchar **trusted_parts = NULL;
	gchar **trusted_host_port = NULL;
	const gchar *trusted_host = NULL;
	gint trusted_host_len;

	/* params of the msg's uri */
	const gchar  *host = NULL;
	gint port;
	gint host_len;

	uri = soup_message_get_uri (msg);
	/* split trusted uri into scheme and host/port */
	if (strstr (trusted, "://")) {
		trusted_parts = g_strsplit (trusted, "://", -1);

		/* The scheme has to match exactly */
		if (g_ascii_strcasecmp (trusted_parts[0],
                                  soup_uri_get_scheme (uri))) {
			goto out;
		}
		if (strlen (trusted_parts[1]) == 0) {
			/* scheme only, we're done */
			ret = TRUE;
			goto out;
		} else
			trusted_host = trusted_parts[1];
	} else {
		trusted_host = trusted;
	}

	trusted_host_port = g_strsplit (trusted_host, ":", 2);
	/* If we got a port in the trusted uri it has to match exactly */
	if (g_strv_length (trusted_host_port) > 1) {
		port = g_ascii_strtoll (trusted_host_port[1], NULL, 10);
		if (port != soup_uri_get_port (uri)) {
			goto out;
		}
	}

	trusted_host = trusted_host_port[0];
	host = soup_uri_get_host (uri);
	if (g_str_has_suffix (host, trusted_host)) {
		/* if the msg host ends with host from the trusted uri, then make
		 * sure it is either an exact match, or prefixed with a dot. We
		 * don't want "foobar.com" to match "bar.com"
		 */
		if (g_ascii_strcasecmp (host, trusted_host) == 0) {
			ret = TRUE;
			goto out;
		} else {
			/* we don't want example.com to match fooexample.com */
			trusted_host_len = strlen (trusted_host);
			host_len = strlen (host);
			if (host[host_len - trusted_host_len - 1] == '.') {
				ret = TRUE;
			}
		}
	}
out:
	g_strfreev (trusted_parts);
	g_strfreev (trusted_host_port);
	return ret;
}

static gboolean
check_auth_trusted_uri (SoupAuthNegotiate *negotiate, SoupMessage *msg)
{
	SoupAuthNegotiatePrivate *priv =
		SOUP_AUTH_NEGOTIATE_GET_PRIVATE (negotiate);
	int i;

	g_return_val_if_fail (negotiate != NULL, FALSE);
	g_return_val_if_fail (priv != NULL, FALSE);
	g_return_val_if_fail (msg != NULL, FALSE);

	/* If no trusted uris are set, we allow all https uris */
	if (!trusted_uris) {
		return match_base_uri (msg, "https://");
	}

	for (i = 0; i < g_strv_length (trusted_uris); i++) {
		if (match_base_uri (msg, trusted_uris[i]))
			return TRUE;
	}
	return FALSE;
}
