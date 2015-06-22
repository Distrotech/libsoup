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
char       *soup_xmlrpc_build_request  (const gchar *method_name,
					 GVariant    *params,
					 GError     **error);
SoupMessage *soup_xmlrpc_message_new    (const char *uri,
					 const char *method_name,
					 GVariant    *params,
					 GError     **error);
GVariant    *soup_xmlrpc_parse_response (const char *method_response,
					 int         length,
					 const char *signature,
					 GError     **error);

/* XML-RPC server */
typedef struct _SoupXMLRPCParams SoupXMLRPCParams;
void         soup_xmlrpc_params_free          (SoupXMLRPCParams  *self);
GVariant    *soup_xmlrpc_params_parse         (SoupXMLRPCParams  *self,
					       const char       *signature,
					       GError           **error);
char       *soup_xmlrpc_parse_request        (const gchar       *method_call,
					       int               length,
					       SoupXMLRPCParams **params,
					       GError           **error);
char       *soup_xmlrpc_parse_request_full   (const gchar       *method_call,
					       int               length,
					       const char       *signature,
					       GVariant         **parameters,
					       GError           **error);
char       *soup_xmlrpc_build_response       (GVariant          *value,
					       GError           **error);
char       *soup_xmlrpc_build_fault          (int               fault_code,
					       const char       *fault_format,
					       ...) G_GNUC_PRINTF (2, 3);
gboolean     soup_xmlrpc_message_set_response (SoupMessage       *msg,
					       GVariant          *value,
					       GError           **error);
void         soup_xmlrpc_message_set_fault    (SoupMessage       *msg,
					       int               fault_code,
					       const char       *fault_format,
					       ...) G_GNUC_PRINTF (3, 4);

/* Utils */
GVariant *soup_xmlrpc_new_custom   (const char *type,
				    const char *value);
GVariant *soup_xmlrpc_new_datetime (time_t       timestamp);

G_END_DECLS

#endif /* SOUP_XMLRPC_VARIANT_H */
