/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2015 - Collabora Ltd.
 */

#ifndef SOUP_XMLRPC_VARIANT_H
#define SOUP_XMLRPC_VARIANT_H 1

#include <libsoup/soup-types.h>
#include <libsoup/soup-xmlrpc.h>

G_BEGIN_DECLS

/* XML-RPC client */
gchar       *soup_xmlrpc_build_request  (const gchar *method_name,
					 GVariant    *params,
					 GError     **error);
SoupMessage *soup_xmlrpc_message_new    (const gchar *uri,
					 const gchar *method_name,
					 GVariant    *params,
					 GError     **error);
GVariant    *soup_xmlrpc_parse_response (const gchar *method_response,
					 gint         length,
					 const gchar *signature,
					 GError     **error);

/* XML-RPC server */
typedef struct _SoupXMLRPCParams SoupXMLRPCParams;
void         soup_xmlrpc_params_free          (SoupXMLRPCParams  *self);
GVariant    *soup_xmlrpc_params_parse         (SoupXMLRPCParams  *self,
					       const gchar       *signature,
					       GError           **error);
gchar       *soup_xmlrpc_parse_request        (const gchar       *method_call,
					       gint               length,
					       SoupXMLRPCParams **params,
					       GError           **error);
gchar       *soup_xmlrpc_parse_request_full   (const gchar       *method_call,
					       gint               length,
					       const gchar       *signature,
					       GVariant         **parameters,
					       GError           **error);
gchar       *soup_xmlrpc_build_response       (GVariant          *value,
					       GError           **error);
gboolean     soup_xmlrpc_message_set_response (SoupMessage       *msg,
					       GVariant          *value,
					       GError           **error);



G_END_DECLS

#endif /* SOUP_XMLRPC_VARIANT_H */
