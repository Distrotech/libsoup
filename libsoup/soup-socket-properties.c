/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2013 Red Hat, Inc.
 */

#include "soup-socket-properties.h"
#include "soup.h"

SoupSocketProperties *
soup_socket_properties_new (GMainContext   *async_context,
			    gboolean        use_thread_context,
			    GProxyResolver *proxy_resolver,
			    SoupAddress    *local_addr,
			    GTlsDatabase   *tlsdb,
			    gboolean        ssl_strict,
			    guint           io_timeout,
			    guint           idle_timeout)
{
	SoupSocketProperties *props;

	props = g_slice_new (SoupSocketProperties);
	props->ref_count = 1;

	props->async_context = async_context ? g_main_context_ref (async_context) : NULL;
	props->use_thread_context = use_thread_context;

	props->proxy_resolver = proxy_resolver ? g_object_ref (proxy_resolver) : NULL;
	props->local_addr = local_addr ? g_object_ref (local_addr) : NULL;

	props->tlsdb = tlsdb ? g_object_ref (tlsdb) : NULL;
	props->ssl_strict = ssl_strict;

	props->io_timeout = io_timeout;
	props->idle_timeout = idle_timeout;

	return props;
}

SoupSocketProperties *
soup_socket_properties_ref (SoupSocketProperties *props)
{
	props->ref_count++;
	return props;
}

void
soup_socket_properties_unref (SoupSocketProperties *props)
{
	if (--props->ref_count)
		return;

	g_clear_pointer (&props->async_context, g_main_context_unref);
	g_clear_object (&props->proxy_resolver);
	g_clear_object (&props->local_addr);
	g_clear_object (&props->tlsdb);

	g_slice_free (SoupSocketProperties, props);
}

void
soup_socket_properties_push_async_context (SoupSocketProperties *props)
{
	if (props->async_context && !props->use_thread_context)
		g_main_context_push_thread_default (props->async_context);
}

void
soup_socket_properties_pop_async_context (SoupSocketProperties *props)
{
	if (props->async_context && !props->use_thread_context)
		g_main_context_pop_thread_default (props->async_context);
}

G_DEFINE_BOXED_TYPE (SoupSocketProperties, soup_socket_properties, soup_socket_properties_ref, soup_socket_properties_unref)
