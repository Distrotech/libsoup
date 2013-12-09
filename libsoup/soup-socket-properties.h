/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef SOUP_SOCKET_PROPERTIES_H
#define SOUP_SOCKET_PROPERTIES_H 1

#include "soup-types.h"

G_BEGIN_DECLS

typedef struct {
	GMainContext *async_context;
	gboolean use_thread_context;

	GProxyResolver *proxy_resolver;
	SoupAddress *local_addr;

	GTlsDatabase *tlsdb;
	gboolean ssl_strict;

	guint io_timeout;
	guint idle_timeout;

	/*< private >*/
	guint ref_count;
} SoupSocketProperties;

GType soup_socket_properties_get_type (void);
#define SOUP_TYPE_SOCKET_PROPERTIES (soup_socket_properties_get_type ())

SoupSocketProperties *soup_socket_properties_new   (GMainContext   *async_context,
						    gboolean        use_thread_context,
						    GProxyResolver *proxy_resolver,
						    SoupAddress    *local_addr,
						    GTlsDatabase   *tlsdb,
						    gboolean        ssl_strict,
						    guint           io_timeout,
						    guint           idle_timeout);

SoupSocketProperties *soup_socket_properties_ref   (SoupSocketProperties *props);
void                  soup_socket_properties_unref (SoupSocketProperties *props);

void soup_socket_properties_push_async_context (SoupSocketProperties *props);
void soup_socket_properties_pop_async_context  (SoupSocketProperties *props);

G_END_DECLS

#endif /* SOUP_SOCKET_PROPERTIES_H */
