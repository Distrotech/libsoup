/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-xmlrpc.c: XML-RPC parser/generator
 *
 * Copyright 2007 Red Hat, Inc.
 * Copyright 2007 OpenedHand Ltd.
 * Copyright 2015 Collabora ltd.
 *
 * Author:
 *   Eduardo Lima Mitev  <elima@igalia.com>
 *   Xavier Claessens <xavier.claessens@collabora.com>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <errno.h>
#include <libxml/tree.h>
#include "soup-xmlrpc-variant.h"
#include "soup.h"

static gboolean insert_value (xmlNode  *parent, GVariant *value, GError **error);

static gboolean
insert_array (xmlNode *parent, GVariant *value, GError **error)
{
	xmlNode *node;
	GVariantIter iter;
	GVariant *child;

	node = xmlNewChild (parent, NULL,
	                    (const xmlChar *)"array", NULL);
	node = xmlNewChild (node, NULL,
	                    (const xmlChar *)"data", NULL);

	g_variant_iter_init (&iter, value);
	while ((child = g_variant_iter_next_value (&iter))) {
		if (!insert_value (node, child, error)) {
			g_variant_unref (child);
			return FALSE;
		}
		g_variant_unref (child);
	}

	return TRUE;
}

static gboolean
insert_struct_member (xmlNode *parent, GVariant *value, GError **error)
{
	xmlNode *member;
	GVariant *mname;
	GVariant *mvalue;
	gboolean ret = FALSE;

	mname = g_variant_get_child_value (value, 0);
	mvalue = g_variant_get_child_value (value, 1);

	if (g_variant_classify (mname) != G_VARIANT_CLASS_STRING) {
		g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
			     "Only string keys are supported in dictionaries, got %s",
			     g_variant_get_type_string (mname));
		goto fail;
	}

	member = xmlNewChild (parent, NULL,
	                      (const xmlChar *)"member", NULL);

	xmlNewTextChild (member, NULL,
	                 (const xmlChar *)"name",
	                 (const xmlChar *)g_variant_get_string (mname, NULL));

	ret = insert_value (member, mvalue, error);

fail:
	g_variant_unref (mname);
	g_variant_unref (mvalue);

	return ret;
}

static gboolean
insert_struct (xmlNode *parent, GVariant *value, GError **error)
{
	xmlNode *struct_node;
	GVariantIter iter;
	GVariant *child;

	struct_node = xmlNewChild (parent, NULL,
	                           (const xmlChar *)"struct", NULL);

	g_variant_iter_init (&iter, value);
	while ((child = g_variant_iter_next_value (&iter))) {
		if (!insert_struct_member (struct_node, child, error)) {
			g_variant_unref (child);
			return FALSE;
		}
		g_variant_unref (child);
	}

	return TRUE;
}

static gboolean
insert_value (xmlNode *parent, GVariant *value, GError **error)
{
	xmlNode *xvalue;
	const char *type_str = NULL;
	char buf[128];

	xvalue = xmlNewChild (parent, NULL, (const xmlChar *)"value", NULL);

	switch (g_variant_classify (value)) {
	case G_VARIANT_CLASS_BOOLEAN:
		snprintf (buf, sizeof (buf), "%d", g_variant_get_boolean (value));
		type_str = "boolean";
		break;
	case G_VARIANT_CLASS_BYTE:
		snprintf (buf, sizeof (buf), "%d", g_variant_get_byte (value));
		type_str = "int";
		break;
	case G_VARIANT_CLASS_INT16:
		snprintf (buf, sizeof (buf), "%d", g_variant_get_int16 (value));
		type_str = "int";
		break;
	case G_VARIANT_CLASS_UINT16:
		snprintf (buf, sizeof (buf), "%d", g_variant_get_uint16 (value));
		type_str = "int";
		break;
	case G_VARIANT_CLASS_INT32:
		snprintf (buf, sizeof (buf), "%d", g_variant_get_int32 (value));
		type_str = "int";
		break;
	case G_VARIANT_CLASS_UINT32:
		snprintf (buf, sizeof (buf), "%u", g_variant_get_uint32 (value));
		type_str = "i8";
		break;
	case G_VARIANT_CLASS_INT64:
		snprintf (buf, sizeof (buf), "%"G_GINT64_FORMAT, g_variant_get_int64 (value));
		type_str = "i8";
		break;
	case G_VARIANT_CLASS_DOUBLE:
		g_ascii_dtostr (buf, sizeof (buf), g_variant_get_double (value));
		type_str = "double";
		break;
	case G_VARIANT_CLASS_STRING:
	case G_VARIANT_CLASS_OBJECT_PATH:
	case G_VARIANT_CLASS_SIGNATURE:
		xmlNewTextChild (xvalue, NULL,
		                 (const xmlChar *)"string",
		                 (const xmlChar *)g_variant_get_string (value, NULL));
		break;
	case G_VARIANT_CLASS_VARIANT: {
		GVariant *child;

		xmlUnlinkNode (xvalue);
		xmlFreeNode (xvalue);

		child = g_variant_get_variant (value);
		if (!insert_value (parent, child, error)) {
			g_variant_unref (child);
			return FALSE;
		}
		g_variant_unref (child);
		break;
	}
	case G_VARIANT_CLASS_ARRAY: {
		if (g_variant_is_of_type (value, G_VARIANT_TYPE_BYTESTRING)) {
			char *encoded;

			encoded = g_base64_encode (g_variant_get_data (value),
			                           g_variant_get_size (value));
			xmlNewChild (xvalue, NULL,
			             (const xmlChar *)"base64",
			             (const xmlChar *)encoded);
			g_free (encoded);
		} else if (g_variant_is_of_type (value, G_VARIANT_TYPE_DICTIONARY)) {
			if (!insert_struct (xvalue, value, error))
				return FALSE;
		} else {
			if (!insert_array (xvalue, value, error))
				return FALSE;
		}

		break;
	}
	case G_VARIANT_CLASS_TUPLE: {
		/* Special case for custom types */
		if (g_variant_is_of_type (value, G_VARIANT_TYPE ("(oss)"))) {
			const char *path;
			const char *type;
			const char *v;

			g_variant_get (value, "(&o&s&s)", &path, &type, &v);
			if (g_str_equal (path, "/org/gnome/libsoup/ExtensionType")) {
				xmlNewTextChild (xvalue, NULL,
				                 (const xmlChar *)type,
				                 (const xmlChar *)v);
				break;
			}
		}

		if (!insert_array (xvalue, value, error))
			return FALSE;
		break;
	}
	case G_VARIANT_CLASS_DICT_ENTRY: {
		xmlNode *node;

		node = xmlNewChild (xvalue, NULL,
		                    (const xmlChar *)"struct", NULL);
		if (!insert_struct_member (node, value, error))
			return FALSE;
		break;
	}
	case G_VARIANT_CLASS_HANDLE:
	case G_VARIANT_CLASS_MAYBE:
	case G_VARIANT_CLASS_UINT64:
	default:
		g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
			     "Unsupported type: %s", g_variant_get_type_string (value));
		goto fail;
	}

	if (type_str != NULL) {
		xmlNewTextChild (xvalue, NULL,
		                 (const xmlChar *)type_str,
		                 (const xmlChar *)buf);
	}

	return TRUE;

fail:
	return FALSE;
}

/**
 * soup_xmlrpc_build_request:
 * @method_name: the name of the XML-RPC method
 * @params: a #GVariant tuple
 * @error: a #GError, or %NULL
 *
 * This creates an XML-RPC methodCall and returns it as a string.
 * This is the low-level method that soup_xmlrpc_message_new() is
 * built on.
 *
 * @params is a #GVariant tuple representing the method parameters.
 *
 * Serialization details:
 *  - "a{s*}" and "{s*}" are serialized as &lt;struct&gt;
 *  - "ay" are serialized as &lt;base64&gt;
 *  - Other arrays and tuples are serialized as &lt;array&gt;
 *  - booleans are serialized as &lt;boolean&gt;
 *  - byte, int16, uint16 and int32 are serialized as &lt;int&gt;
 *  - uint32 and int64 are serialized as nonstandard &lt;i8&gt;
 *  - doubles are serialized as &lt;double&gt;
 *  - Strings, object-paths and signatures are serialized as &lt;string&gt;
 *  - Variants (i.e. "v" type) are unwrapped and their child is serialized.
 *  - #GVariant created by soup_xmlrpc_new_datetime() are serialized as
 *    &lt;dateTime.iso8601&gt;
 *  - Other types are not supported and will return %NULL and set @error.
 *    This notably includes: uint64, maybes and dictionaries with non-string
 *    keys.
 *
 * If @params is floating, it is consumed.
 *
 * Return value: the text of the methodCall, or %NULL on error.
 * Since: 2.52
 **/
char *
soup_xmlrpc_build_request (const char *method_name,
			   GVariant    *params,
			   GError     **error)
{
	xmlDoc *doc;
	xmlNode *node, *param;
	xmlChar *xmlbody;
	GVariantIter iter;
	GVariant *child;
	int len;
	char *body = NULL;

	g_variant_ref_sink (params);

	if (!g_variant_is_of_type (params, G_VARIANT_TYPE_TUPLE)) {
		g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
			     "params must be a tuple but is %s",
			     g_variant_get_type_string (params));
		goto fail;
	}

	doc = xmlNewDoc ((const xmlChar *)"1.0");
	doc->standalone = FALSE;
	doc->encoding = xmlCharStrdup ("UTF-8");

	node = xmlNewDocNode (doc, NULL, (const xmlChar *)"methodCall", NULL);
	xmlDocSetRootElement (doc, node);
	xmlNewChild (node, NULL, (const xmlChar *)"methodName",
		     (const xmlChar *)method_name);

	node = xmlNewChild (node, NULL, (const xmlChar *)"params", NULL);
	g_variant_iter_init (&iter, params);
	while ((child = g_variant_iter_next_value (&iter))) {
		param  = xmlNewChild (node, NULL,
				      (const xmlChar *)"param", NULL);
		if (!insert_value (param, child, error)) {
			xmlFreeDoc (doc);
			g_variant_unref (child);
			g_variant_unref (params);
			return NULL;
		}
		g_variant_unref (child);
	}

	xmlDocDumpMemory (doc, &xmlbody, &len);
	body = g_strndup ((char *)xmlbody, len);
	xmlFree (xmlbody);

	xmlFreeDoc (doc);
	g_variant_unref (params);

fail:
	return body;
}

/**
 * soup_xmlrpc_message_new:
 * @uri: URI of the XML-RPC service
 * @method_name: the name of the XML-RPC method to invoke at @uri
 * @params: a #GVariant tuple
 * @error: a #GError, or %NULL
 *
 * Creates an XML-RPC methodCall and returns a #SoupMessage, ready
 * to send, for that method call.
 *
 * See soup_xmlrpc_build_request() for serialization details.
 *
 * If @params is floating, it is consumed.
 *
 * Returns: (transfer full): a #SoupMessage encoding the
 *  indicated XML-RPC request, or %NULL on error.
 * Since: 2.52
 **/
SoupMessage *
soup_xmlrpc_message_new (const char *uri,
			 const char *method_name,
			 GVariant    *params,
			 GError     **error)
{
	SoupMessage *msg;
	char *body;

	body = soup_xmlrpc_build_request (method_name, params, error);
	if (!body)
		return NULL;

	msg = soup_message_new ("POST", uri);
	soup_message_set_request (msg, "text/xml", SOUP_MEMORY_TAKE,
				  body, strlen (body));
	return msg;
}

/**
 * soup_xmlrpc_build_response:
 * @value: the return value
 * @error: a #GError, or %NULL
 *
 * This creates a (successful) XML-RPC methodResponse and returns it
 * as a string. To create a fault response, use soup_xmlrpc_build_fault(). This
 * is the low-level method that soup_xmlrpc_message_set_response() is built on.
 *
 * See soup_xmlrpc_build_request() for serialization details.
 *
 * If @value is floating, it is consumed.
 *
 * Returns: the text of the methodResponse, or %NULL on error.
 * Since: 2.52
 **/
char *
soup_xmlrpc_build_response (GVariant *value, GError **error)
{
	xmlDoc *doc;
	xmlNode *node;
	xmlChar *xmlbody;
	char *body;
	int len;

	g_variant_ref_sink (value);

	doc = xmlNewDoc ((const xmlChar *)"1.0");
	doc->standalone = FALSE;
	doc->encoding = xmlCharStrdup ("UTF-8");

	node = xmlNewDocNode (doc, NULL,
			      (const xmlChar *)"methodResponse", NULL);
	xmlDocSetRootElement (doc, node);

	node = xmlNewChild (node, NULL, (const xmlChar *)"params", NULL);
	node = xmlNewChild (node, NULL, (const xmlChar *)"param", NULL);
	if (!insert_value (node, value, error)) {
		xmlFreeDoc (doc);
		g_variant_unref (value);
		return NULL;
	}

	xmlDocDumpMemory (doc, &xmlbody, &len);
	body = g_strndup ((char *)xmlbody, len);
	xmlFree (xmlbody);

	xmlFreeDoc (doc);
	g_variant_unref (value);

	return body;
}

/**
 * soup_xmlrpc_message_set_response:
 * @msg: an XML-RPC request
 * @value: a #GVariant
 * @error: a #GError, or %NULL
 *
 * Sets the status code and response body of @msg to indicate a
 * successful XML-RPC call, with a return value given by @value. To set a
 * fault response, use soup_xmlrpc_set_fault().
 *
 * See soup_xmlrpc_build_request() for serialization details.
 *
 * If @value is floating, it is consumed.
 *
 * Returns: %TRUE on success, %FALSE otherwise.
 * Since: 2.52
 **/
gboolean
soup_xmlrpc_message_set_response (SoupMessage *msg, GVariant *value, GError **error)
{
	char *body;

	body = soup_xmlrpc_build_response (value, error);
	if (!body)
		return FALSE;

	soup_message_set_status (msg, SOUP_STATUS_OK);
	soup_message_set_response (msg, "text/xml", SOUP_MEMORY_TAKE,
				   body, strlen (body));
	return TRUE;
}

static GVariant *parse_value (xmlNode *node, const char **signature, GError **error);

static xmlNode *
find_real_node (xmlNode *node)
{
	while (node && (node->type == XML_COMMENT_NODE ||
			xmlIsBlankNode (node)))
		node = node->next;
	return node;
}

static char *
signature_get_next_complete_type (const char **signature)
{
	GVariantClass class;
	const char *initial_signature;
	char *result;

	/* here it is assumed that 'signature' is a valid type string */

	initial_signature = *signature;
	class = (*signature)[0];

	if (class == G_VARIANT_CLASS_TUPLE || class == G_VARIANT_CLASS_DICT_ENTRY) {
		char stack[256] = {0};
		guint stack_len = 0;

		do {
			if ((*signature)[0] == G_VARIANT_CLASS_TUPLE) {
				stack[stack_len] = ')';
				stack_len++;
			}
			else if ( (*signature)[0] == G_VARIANT_CLASS_DICT_ENTRY) {
				stack[stack_len] = '}';
				stack_len++;
			}

			(*signature)++;

			if ( (*signature)[0] == stack[stack_len - 1])
				stack_len--;
		} while (stack_len > 0);

		(*signature)++;
	} else if (class == G_VARIANT_CLASS_ARRAY || class == G_VARIANT_CLASS_MAYBE) {
		char *tmp_sig;

		(*signature)++;
		tmp_sig = signature_get_next_complete_type (signature);
		g_free (tmp_sig);
	} else {
		(*signature)++;
	}

	result = g_strndup (initial_signature, (*signature) - initial_signature);

	return result;
}

static GVariant *
parse_array (xmlNode *node, const char **signature, GError **error)
{
	GVariant *variant = NULL;
	char *child_signature = NULL;
	char *array_signature = NULL;
	const char *tmp_signature;
	gboolean is_tuple = FALSE;
	xmlNode *member;
	GVariantBuilder builder;
	gboolean is_params = FALSE;

	if (signature && *signature[0] == G_VARIANT_CLASS_VARIANT)
		signature = NULL;

	if (g_str_equal (node->name, "array")) {
		node = find_real_node (node->children);
		if (!g_str_equal (node->name, "data")) {
			g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
				     "<data> expected but got '%s'", node->name);
			goto fail;
		}
	} else if (g_str_equal (node->name, "params")) {
		is_params = TRUE;
	} else {
		g_assert_not_reached ();
	}

	if (signature != NULL) {
		if ((*signature)[0] == G_VARIANT_CLASS_TUPLE) {
			tmp_signature = *signature;
			array_signature = signature_get_next_complete_type (&tmp_signature);
			is_tuple = TRUE;
		}
		(*signature)++;
		child_signature = signature_get_next_complete_type (signature);
	} else {
		child_signature = g_strdup ("v");
	}

	if (!array_signature)
		array_signature = g_strdup_printf ("a%s", child_signature);
	g_variant_builder_init (&builder, G_VARIANT_TYPE (array_signature));

	for (member = find_real_node (node->children);
	     member;
	     member = find_real_node (member->next)) {
		GVariant *child;
		xmlNode *xval = member;

		if (is_params) {
			if (!g_str_equal (member->name, "param")) {
				g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
					     "<param> expected but got '%s'", member->name);
				goto fail;
			}
			xval = find_real_node (member->children);
		}

		if (strcmp ((const char *)xval->name, "value") != 0) {
			g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
				     "<value> expected but got '%s'", xval->name);
			goto fail;
		}

		if (is_tuple && child_signature[0] == ')') {
			g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
				     "Too many values for tuple");
			goto fail;
		}

		tmp_signature = child_signature;
		child = parse_value (xval, &tmp_signature, error);
		if (child == NULL)
			goto fail;

		if (is_tuple) {
			g_free (child_signature),
			child_signature = signature_get_next_complete_type (signature);
		}

		g_variant_builder_add_value (&builder, child);
	}

	if (is_tuple && child_signature[0] != ')') {
		g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
			     "Too few values for tuple");
		goto fail;
	}

	variant = g_variant_builder_end (&builder);

fail:
	g_variant_builder_clear (&builder);
	g_free (child_signature);
	g_free (array_signature);

	/* compensate the (*signature)++ call at the end of 'recurse()' */
	if (signature)
		(*signature)--;

	return variant;
}

static void
parse_dict_entry_signature (const char **signature,
			    char       **entry_signature,
			    char       **key_signature,
			    char       **value_signature)
{
	const char *tmp_sig;

	if (signature)
		*entry_signature = signature_get_next_complete_type (signature);
	else
		*entry_signature = g_strdup ("{sv}");

	tmp_sig = (*entry_signature) + 1;
	*key_signature = signature_get_next_complete_type (&tmp_sig);
	*value_signature = signature_get_next_complete_type (&tmp_sig);
}

static GVariant *
parse_dictionary (xmlNode *node, const char **signature, GError **error)
{
	GVariant *variant = NULL;
	char *dict_signature;
	char *entry_signature;
	char *key_signature;
	char *value_signature;
	GVariantBuilder builder;
	xmlNode *member;

	if (signature && *signature[0] == G_VARIANT_CLASS_VARIANT)
		signature = NULL;

	if (signature)
		(*signature)++;

	parse_dict_entry_signature (signature,
				    &entry_signature,
				    &key_signature,
				    &value_signature);

	dict_signature = g_strdup_printf ("a%s", entry_signature);
	g_variant_builder_init (&builder, G_VARIANT_TYPE (dict_signature));

	if (!g_str_equal (key_signature, "s")) {
		g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
			     "Dictionary key must be string but got '%s'", key_signature);
		goto fail;
	}

	for (member = find_real_node (node->children);
	     member;
	     member = find_real_node (member->next)) {
		xmlNode *child, *mname, *mxval;
		const char *tmp_signature;
		GVariant *value;
		xmlChar *content;

		if (strcmp ((const char *)member->name, "member") != 0) {
			g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
				     "<member> expected but got '%s'", member->name);
			goto fail;
		}

		mname = mxval = NULL;

		for (child = find_real_node (member->children);
		     child;
		     child = find_real_node (child->next)) {
			if (!strcmp ((const char *)child->name, "name"))
				mname = child;
			else if (!strcmp ((const char *)child->name, "value"))
				mxval = child;
			else {
				g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
					     "<name> or <value> expected but got '%s'", child->name);
				goto fail;
			}
		}

		if (!mname || !mxval) {
			g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
				     "Missing name or value in <member>");
			goto fail;
		}

		tmp_signature = value_signature;
		value = parse_value (mxval, &tmp_signature, error);
		if (!value)
			goto fail;

		content = xmlNodeGetContent (mname);
		g_variant_builder_open (&builder, G_VARIANT_TYPE (entry_signature));
		g_variant_builder_add (&builder, "s", content);
		g_variant_builder_add_value (&builder, value);
		g_variant_builder_close (&builder);
		xmlFree (content);
	}

	variant = g_variant_builder_end (&builder);

fail:
	g_variant_builder_clear (&builder);
	g_free (value_signature);
	g_free (key_signature);
	g_free (entry_signature);
	g_free (dict_signature);

	/* compensate the (*signature)++ call at the end of 'recurse()' */
	if (signature != NULL)
		(*signature)--;

	return variant;
}

static GVariant *
parse_number (xmlNode *typenode, GVariantClass class, GError **error)
{
	xmlChar *content;
	const char *str;
	char *endptr;
	gint64 num = 0;
	guint64 unum = 0;
	GVariant *variant = NULL;

	content = xmlNodeGetContent (typenode);
	str = (const char *) content;

	errno = 0;

	if (class == G_VARIANT_CLASS_UINT64)
		unum = g_ascii_strtoull (str, &endptr, 10);
	else
		num = g_ascii_strtoll (str, &endptr, 10);

	if (errno || endptr == str) {
		g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
			     "Couldn't parse number '%s'", str);
		goto fail;
	}

#define RANGE(v, min, max) \
G_STMT_START{ \
	if (v < min || v > max) { \
		g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS, \
			     "Number out of range '%s'", str); \
		goto fail; \
	} \
} G_STMT_END

	switch (class) {
	case G_VARIANT_CLASS_BOOLEAN:
		RANGE (num, 0, 1);
		variant = g_variant_new_boolean (num);
		break;
	case G_VARIANT_CLASS_BYTE:
		RANGE (num, 0, G_MAXUINT8);
		variant = g_variant_new_byte (num);
		break;
	case G_VARIANT_CLASS_INT16:
		RANGE (num, G_MININT16, G_MAXINT16);
		variant = g_variant_new_int16 (num);
		break;
	case G_VARIANT_CLASS_UINT16:
		RANGE (num, 0, G_MAXUINT16);
		variant = g_variant_new_uint16 (num);
		break;
	case G_VARIANT_CLASS_INT32:
		RANGE (num, G_MININT32, G_MAXINT32);
		variant = g_variant_new_int32 (num);
		break;
	case G_VARIANT_CLASS_UINT32:
		RANGE (num, 0, G_MAXUINT32);
		variant = g_variant_new_uint32 (num);
		break;
	case G_VARIANT_CLASS_INT64:
		RANGE (num, G_MININT64, G_MAXINT64);
		variant = g_variant_new_int64 (num);
		break;
	case G_VARIANT_CLASS_UINT64:
		RANGE (unum, 0, G_MAXUINT64);
		variant = g_variant_new_uint64 (unum);
		break;
	default:
		g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
			     "<%s> node does not match signature",
			     (const char *)typenode->name);
		goto fail;
	}

fail:
	xmlFree (content);

	return variant;
}

static GVariant *
parse_double (xmlNode *typenode, GError **error)
{
	GVariant *variant = NULL;
	xmlChar *content;
	const char *str;
	char *endptr;
	gdouble d;

	content = xmlNodeGetContent (typenode);
	str = (const char *) content;

	errno = 0;
	d = g_ascii_strtod (str, &endptr);
	if (errno || endptr == str) {
		g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
			     "Couldn't parse double '%s'", str);
		goto fail;
	}

	variant = g_variant_new_double (d);

fail:
	xmlFree (content);

	return variant;
}

static GVariant *
parse_base64 (xmlNode *typenode, GError **error)
{
	GVariant *variant;
	xmlChar *content;
	guchar *decoded;
	gsize len;

	content = xmlNodeGetContent (typenode);
	decoded = g_base64_decode ((char *)content, &len);
	variant = g_variant_new_from_data (G_VARIANT_TYPE ("ay"),
					   decoded, len,
					   TRUE,
					   g_free, decoded);
	xmlFree (content);

	return variant;
}

static GVariant *
parse_value (xmlNode *node, const char **signature, GError **error)
{
	xmlNode *typenode;
	const char *typename;
	xmlChar *content = NULL;
	GVariant *variant = NULL;
	GVariantClass class = G_VARIANT_CLASS_VARIANT;

	if (signature)
		class = *signature[0];

	if (g_str_equal ((const char *)node->name, "value")) {
		typenode = find_real_node (node->children);
		if (!typenode) {
			/* If no typenode, assume value's content is string */
			typename = "string";
			typenode = node;
		} else {
			typename = (const char *)typenode->name;
		}
	} else if (g_str_equal ((const char *)node->name, "params")) {
		typenode = node;
		typename = "params";
	} else {
		g_assert_not_reached ();
	}

	if (g_str_equal (typename, "boolean")) {
		if (class != G_VARIANT_CLASS_VARIANT && class != G_VARIANT_CLASS_BOOLEAN) {
			g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
				     "<boolean> node does not match signature");
			goto fail;
		}
		variant = parse_number (typenode, G_VARIANT_CLASS_BOOLEAN, error);
	} else if (g_str_equal (typename, "int") || g_str_equal (typename, "i4")) {
		if (class == G_VARIANT_CLASS_VARIANT)
			variant = parse_number (typenode, G_VARIANT_CLASS_INT32, error);
		else
			variant = parse_number (typenode, class, error);
	} else if (g_str_equal (typename, "i8")) {
		if (class == G_VARIANT_CLASS_VARIANT)
			variant = parse_number (typenode, G_VARIANT_CLASS_INT64, error);
		else
			variant = parse_number (typenode, class, error);
	} else  if (g_str_equal (typename, "double")) {
		if (class == G_VARIANT_CLASS_VARIANT || class == G_VARIANT_CLASS_DOUBLE) {
			g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
				     "<double> node does not match signature");
			goto fail;
		}
		variant = parse_double (typenode, error);
	} else  if (g_str_equal (typename, "string")) {
		content = xmlNodeGetContent (typenode);
		if (class == G_VARIANT_CLASS_VARIANT || class == G_VARIANT_CLASS_STRING)
			variant = g_variant_new_string ((const char *)content);
		else if (class == G_VARIANT_CLASS_OBJECT_PATH &&
			 g_variant_is_object_path ((const char *)content))
			variant = g_variant_new_object_path ((const char *)content);
		else if (class == G_VARIANT_CLASS_SIGNATURE &&
			 g_variant_is_signature ((const char *)content))
			variant = g_variant_new_signature ((const char *)content);
		else {
			g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
				     "<string> node does not match signature");
			goto fail;
		}
	} else if (g_str_equal (typename, "base64")) {
		if (class != G_VARIANT_CLASS_VARIANT) {
			if (!g_str_has_prefix (*signature, "ay")) {
				g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
					     "<base64> node does not match signature");
				goto fail;
			}
			(*signature)++;
		}
		variant = parse_base64 (typenode, error);
	} else if (g_str_equal (typename, "struct")) {
		if (class != G_VARIANT_CLASS_VARIANT &&
		    !g_str_has_prefix (*signature, "a{")) {
			g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
				     "<struct> node does not match signature");
			goto fail;
		}
		variant = parse_dictionary (typenode, signature, error);
	} else if (g_str_equal (typename, "array") || g_str_equal (typename, "params")) {
		if (class != G_VARIANT_CLASS_VARIANT &&
		    class != G_VARIANT_CLASS_ARRAY &&
		    class != G_VARIANT_CLASS_TUPLE) {
			g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
				     "<%s> node does not match signature", typename);
			goto fail;
		}
		variant = parse_array (typenode, signature, error);
	} else if (g_str_equal (typename, "dateTime.iso8601")) {
		GTimeVal t;

		if (class != G_VARIANT_CLASS_VARIANT &&
		    class != G_VARIANT_CLASS_INT64) {
			g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
				     "<dateTime.iso8601> node does not match signalture");
			goto fail;
		}

		content = xmlNodeGetContent (node);
		if (!g_time_val_from_iso8601 ((char *)content, &t)) {
			g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
				     "Couldn't parse date: %s", content);
			goto fail;
		}

		variant = g_variant_new_int64 (t.tv_sec);
	} else {
		g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
			     "Unknown node name %s", typename);
		goto fail;
	}

	if (variant && signature) {
		if (class == G_VARIANT_CLASS_VARIANT)
			variant = g_variant_new_variant (variant);
		(*signature)++;
	}

fail:
	if (content)
		xmlFree (content);

	return variant;
}

/**
 * SoupXMLRPCParams:
 *
 * Opaque structure containing an XML-RPC value. Can be parsed using
 * soup_xmlrpc_params_parse() and freed with soup_xmlrpc_params_free().
 *
 * Since: 2.52
 */
struct _SoupXMLRPCParams
{
  xmlNode *node;
};

/**
 * soup_xmlrpc_params_free:
 * @self: a SoupXMLRPCParams
 *
 * Free a #SoupXMLRPCParams returned by soup_xmlrpc_parse_request().
 *
 * Since: 2.52
 */
void
soup_xmlrpc_params_free (SoupXMLRPCParams *self)
{
	g_return_if_fail (self != NULL);

	if (self->node)
		xmlFreeDoc (self->node->doc);
	g_slice_free (SoupXMLRPCParams, self);
}

static SoupXMLRPCParams *
soup_xmlrpc_params_new (xmlNode *node)
{
	SoupXMLRPCParams *self;

	self = g_slice_new (SoupXMLRPCParams);
	self->node = node;

	return self;
}

/**
 * soup_xmlrpc_params_parse:
 * @self: A #SoupXMLRPCParams
 * @signature: (allow-none): A valid #GVariant type string, or %NULL
 * @error: a #GError, or %NULL
 *
 * Parse method parameters returned by soup_xmlrpc_parse_request().
 *
 * See soup_xmlrpc_parse_request_full() for deserialization details.
 *
 * Returns: (transfer full): a new #GVariant, or %NULL
 * Since: 2.52
 */
GVariant *
soup_xmlrpc_params_parse (SoupXMLRPCParams *self,
			  const char      *signature,
			  GError          **error)
{
	GVariant *value = NULL;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (!signature || g_variant_type_string_is_valid (signature), NULL);

	value = parse_value (self->node, signature ? &signature : NULL, error);

	return value ? g_variant_ref_sink (value) : NULL;
}

/**
 * soup_xmlrpc_parse_request:
 * @method_call: the XML-RPC methodCall string
 * @length: the length of @method_call, or -1 if it is NUL-terminated
 * @params: (out): on success, a new #SoupXMLRPCParams
 * @error: a #GError, or %NULL
 *
 * Parses @method_call and return the method name. Method parameters can be
 * parsed later using soup_xmlrpc_params_parse(). If the signature of parameters
 * is known in advance then soup_xmlrpc_parse_request_full() could be used
 * instead.
 *
 * Returns: (transfer full): method's name, or %NULL on error.
 * Since: 2.52
 **/
char *
soup_xmlrpc_parse_request (const char *method_call,
			   int length,
			   SoupXMLRPCParams **params,
			   GError **error)
{
	xmlDoc *doc = NULL;
	xmlNode *node;
	xmlChar *xmlMethodName = NULL;
	char *method_name = NULL;

	doc = xmlParseMemory (method_call,
				  length == -1 ? strlen (method_call) : length);
	if (!doc) {
		g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
			     "Could not parse XML document");
		goto fail;
	}

	node = xmlDocGetRootElement (doc);
	if (!node || strcmp ((const char *)node->name, "methodCall") != 0) {
		g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
			     "<methodCall> node expected");
		goto fail;
	}

	node = find_real_node (node->children);
	if (!node || strcmp ((const char *)node->name, "methodName") != 0) {
		g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
			     "<methodName> node expected");
		goto fail;
	}
	xmlMethodName = xmlNodeGetContent (node);

	if (params) {
		node = find_real_node (node->next);
		if (!node || strcmp ((const char *)node->name, "params") != 0) {
			g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
				     "<params> node expected");
			goto fail;
		}
		*params = soup_xmlrpc_params_new (node);
		doc = NULL;
	}

	method_name = g_strdup ((char *)xmlMethodName);

fail:
	if (doc)
		xmlFreeDoc (doc);
	if (xmlMethodName)
		xmlFree (xmlMethodName);

	return method_name;
}

/**
 * soup_xmlrpc_parse_request_full:
 * @method_call: the XML-RPC methodCall string
 * @length: the length of @method_call, or -1 if it is NUL-terminated
 * @signature: (allow-none): A valid #GVariant type string, or %NULL
 * @parameters: (out): on success, a new #GVariant
 * @error: a #GError, or %NULL
 *
 * Parses @method_call and return the method name and set @parameters.
 * soup_xmlrpc_parse_request() should be used instead if the method name must be
 * known to determine @parameters' signature.
 *
 * Deserialization details:
 *  - If @signalture is provided, &lt;int&gt and &lt;i4&gt can be deserialized
 *    to byte, int16, uint16, int32, uint32, int64, uint64 or handle. Otherwise
 *    it will be int32. If the value is out of range for the target type it will
 *    return an @error.
 *  - &lt;struct&gt; will be deserialized to "a{sv}". @signalture could define
 *    another value type (e.g. "a{ss}").
 *  - &lt;array&gt; will be deserialized to "av". @signalture could define
 *    another element type (e.g. "as") or could be a tuple (e.g. "(ss)").
 *  - &lt;base64&gt; will be deserialized to "ay".
 *  - &lt;string&gt; will be deserialized to "s". @signalture could define
 *    another type ("o" or "g").
 *  - &lt;dateTime.iso8601&gt; will be deserialized to int64 unix timestamp.
 *  - @signature must not have maybes, otherwise an @error is returned.
 *  - Dictionaries must have string keys, otherwise an @error is returned.
 *
 * Returns: (transfer full): method's name, or %NULL on error.
 * Since: 2.52
 **/
char *
soup_xmlrpc_parse_request_full (const char *method_call,
				int         length,
				const char *signature,
				GVariant   **parameters,
				GError     **error)
{
	char *method_name;
	SoupXMLRPCParams *params;

	method_name = soup_xmlrpc_parse_request (method_call,
						 length,
						 parameters ? &params : NULL,
						 error);
	if (!method_name)
		return NULL;

	if (parameters) {
		*parameters = soup_xmlrpc_params_parse (params, signature, error);
		if (*parameters == NULL) {
			g_free (method_name);
			return NULL;
		}
	}

	return method_name;
}

/**
 * soup_xmlrpc_parse_response:
 * @method_response: the XML-RPC methodResponse string
 * @length: the length of @method_response, or -1 if it is NUL-terminated
 * @signature: (allow-none): A valid #GVariant type string, or %NULL
 * @error: a #GError, or %NULL
 *
 * Parses @method_response and returns the return value. If
 * @method_response is a fault, %NULL is returned, and @error
 * will be set to an error in the %SOUP_XMLRPC_FAULT domain, with the error
 * code containing the fault code, and the error message containing
 * the fault string. If @method_response cannot be parsed, %NULL is returned,
 * and @error will be set to an error in the %SOUP_XMLRPC_ERROR domain.
 *
 * See soup_xmlrpc_parse_request_full() for deserialization details.
 *
 * Returns: (transfer full): a new #GVariant, or %NULL
 * Since: 2.52
 **/
GVariant *
soup_xmlrpc_parse_response (const char *method_response,
			    int length,
			    const char *signature,
			    GError **error)
{
	xmlDoc *doc = NULL;
	xmlNode *node;
	GVariant *value = NULL;

	g_return_val_if_fail (!signature || g_variant_type_string_is_valid (signature), NULL);

	doc = xmlParseMemory (method_response,
				  length == -1 ? strlen (method_response) : length);
	if (!doc) {
		g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
			     "Failed to parse response XML");
		goto fail;
	}

	node = xmlDocGetRootElement (doc);
	if (!node || strcmp ((const char *)node->name, "methodResponse") != 0) {
		g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
			     "Missing 'methodResponse' node");
		goto fail;
	}

	node = find_real_node (node->children);
	if (!node) {
		g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
			     "'methodResponse' has no child");
		goto fail;
	}

	if (!strcmp ((const char *)node->name, "fault")) {
		int fault_code;
		const char *fault_string;
		const char *fault_sig = "a{sv}";
		GVariant *fault_val;

		node = find_real_node (node->children);
		if (!node || strcmp ((const char *)node->name, "value") != 0) {
			g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
				     "'fault' has no 'value' child");
			goto fail;
		}

		fault_val = parse_value (node, &fault_sig, error);
		if (!fault_val)
			goto fail;

		if (!g_variant_lookup (fault_val, "faultCode", "i", &fault_code) ||
		    !g_variant_lookup (fault_val, "faultString", "&s", &fault_string))  {
			g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
				     "'fault' missing 'faultCode' or 'faultString'");
			goto fail;
		}
		g_set_error (error, SOUP_XMLRPC_FAULT,
		             fault_code, "%s", fault_string);
		g_variant_unref (fault_val);
	} else if (!strcmp ((const char *)node->name, "params")) {
		node = find_real_node (node->children);
		if (!node || strcmp ((const char *)node->name, "param") != 0) {
			g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
				     "'params' has no 'param' child");
			goto fail;
		}
		node = find_real_node (node->children);
		if (!node || strcmp ((const char *)node->name, "value") != 0) {
			g_set_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS,
				     "'param' has no 'value' child");
			goto fail;
		}
		value = parse_value (node, signature ? &signature : NULL, error);
	}

fail:
	if (doc)
		xmlFreeDoc (doc);
	return value ? g_variant_ref_sink (value) : NULL;
}

/**
 * soup_xmlrpc_new_custom:
 * @type: name for the type node
 * @value: value for the type node
 *
 * Construct a special #GVariant used to serialize a &lt;@type&gt;
 * node containing @value. See soup_xmlrpc_build_request().
 *
 * Returns: a floating #GVariant.
 * Since: 2.52
 */
GVariant *
soup_xmlrpc_new_custom (const char *type, const gchar *value)
{
	return g_variant_new ("(oss)", "/org/gnome/libsoup/ExtensionType",
			      type, value);
}

/**
 * soup_xmlrpc_new_datetime:
 * @timestamp: a unix timestamp
 *
 * Construct a special #GVariant used to serialize a &lt;dateTime.iso8601&gt;
 * node. See soup_xmlrpc_build_request().
 *
 * Returns: a floating #GVariant.
 * Since: 2.52
 */
GVariant *
soup_xmlrpc_new_datetime (time_t timestamp)
{
	SoupDate *date;
	GVariant *variant;
	char *str;

	date = soup_date_new_from_time_t (timestamp);
	str = soup_date_to_string (date, SOUP_DATE_ISO8601_XMLRPC);
	variant = soup_xmlrpc_new_custom ("dateTime.iso8601", str);
	soup_date_free (date);
	g_free (str);

	return variant;
}
