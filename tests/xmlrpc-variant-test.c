/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2015, Collabora ltd.
 */

#include "test-utils.h"

#define BODY_PREFIX \
	"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n" \
	"<methodCall><methodName>MyMethod</methodName>"
#define BODY_SUFFIX \
	"</methodCall>\n"

static void
verify_serialization (GVariant    *value,
		      const gchar *expected_params)
{
	gchar *debug;
	gchar *body;
	gchar *params;
	GError *error = NULL;

	debug = g_variant_print (value, TRUE);

	body = soup_xmlrpc_build_request ("MyMethod", value, &error);
	g_assert_no_error (error);
	g_assert (g_str_has_prefix (body, BODY_PREFIX));
	g_assert (g_str_has_suffix (body, BODY_SUFFIX));

	params = g_strndup (body + strlen (BODY_PREFIX),
	                    strlen (body) - strlen (BODY_PREFIX)
	                                  - strlen (BODY_SUFFIX));

	if (!g_str_equal (params, expected_params))
		g_error ("Failed to serialize '%s':\n"
		         "  expected: %s\n"
		         "  got:      %s\n",
		         debug, expected_params, params);

	g_free (params);
	g_free (body);
	g_free (debug);
}

static void
verify_serialization_fail (GVariant *value)
{
	gchar *body;
	GError *error = NULL;

	body = soup_xmlrpc_build_request ("MyMethod", value, &error);
	g_assert (body == NULL);
	g_assert (error != NULL);
}

static void
test_serializer (void)
{
	verify_serialization (g_variant_new_parsed ("()"),
		"<params/>");
	verify_serialization (g_variant_new_parsed ("(1, 2)"),
		"<params>"
		"<param><value><int>1</int></value></param>"
		"<param><value><int>2</int></value></param>"
		"</params>");
	verify_serialization (g_variant_new_parsed ("((1, 2),)"),
		"<params><param><value><array><data>"
		"<value><int>1</int></value>"
		"<value><int>2</int></value>"
		"</data></array></value></param></params>");
	verify_serialization (g_variant_new_parsed ("({'one', 1},)"),
		"<params><param><value><struct>"
		"<member><name>one</name><value><int>1</int></value></member>"
		"</struct></value></param></params>");
	verify_serialization (g_variant_new_parsed ("([{'one', 1},{'two', 2}],)"),
		"<params><param><value><struct>"
		"<member><name>one</name><value><int>1</int></value></member>"
		"<member><name>two</name><value><int>2</int></value></member>"
		"</struct></value></param></params>");
	verify_serialization (g_variant_new ("(^ay)", "bytestring"),
		"<params><param>"
		"<value><base64>Ynl0ZXN0cmluZwA=</base64></value>"
		"</param></params>");
	verify_serialization (g_variant_new ("(y)", 42),
		"<params>"
		"<param><value><int>42</int></value></param>"
		"</params>");
	verify_serialization (g_variant_new ("(@*)", soup_xmlrpc_new_datetime (1434161309)),
		"<params>"
		"<param><value><dateTime.iso8601>2015-06-13T02:08:29Z</dateTime.iso8601></value></param>"
		"</params>");
	verify_serialization (g_variant_new ("(s)", "<>&"),
		"<params>"
		"<param><value><string>&lt;&gt;&amp;</string></value></param>"
		"</params>");

	verify_serialization_fail (g_variant_new_parsed ("1"));
	verify_serialization_fail (g_variant_new_parsed ("({1, 2},)"));
	verify_serialization_fail (g_variant_new ("(mi)", NULL));
	verify_serialization_fail (g_variant_new ("(u)", 0));
	verify_serialization_fail (g_variant_new ("(t)", G_MAXUINT64));
}

static void
verify_deserialization (GVariant *expected_variant,
			const gchar *signature,
			const gchar *params)
{
	gchar *body;
	gchar *method_name;
	GVariant *variant;
	GError *error = NULL;

	body = g_strconcat (BODY_PREFIX, params, BODY_SUFFIX, NULL);
	method_name = soup_xmlrpc_parse_request_full (body, strlen (body),
						      signature,
						      &variant,
						      &error);
	g_assert_no_error (error);
	g_assert_cmpstr (method_name, ==, "MyMethod");

	if (!g_variant_equal (variant, expected_variant)) {
		gchar *str1, *str2;

		str1 = g_variant_print (expected_variant, TRUE);
		str2 = g_variant_print (variant, TRUE);
		g_error ("Failed to deserialize '%s':\n"
		         "  expected: %s\n"
		         "  got:      %s\n",
		         params, str1, str2);
		g_free (str1);
		g_free (str2);
	}

	g_variant_unref (variant);
	g_free (method_name);
	g_free (body);
}

static void
verify_deserialization_fail (const gchar *signature,
			     const gchar *params)
{
	gchar *body;
	gchar *method_name;
	GVariant *variant;
	GError *error = NULL;

	body = g_strconcat (BODY_PREFIX, params, BODY_SUFFIX, NULL);
	method_name = soup_xmlrpc_parse_request_full (body, strlen (body),
						      signature,
						      &variant,
						      &error);
	g_assert_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS);
	g_assert (method_name == NULL);

	g_free (body);
}

static void
test_deserializer (void)
{
	verify_deserialization (g_variant_new_parsed ("@av []"),
		NULL,
		"<params/>");
	verify_deserialization (g_variant_new_parsed ("()"),
		"()",
		"<params/>");
	verify_deserialization (g_variant_new_parsed ("(@y 1,@n 2)"),
		"(yn)",
		"<params>"
		"<param><value><int>1</int></value></param>"
		"<param><value><int>2</int></value></param>"
		"</params>");
	verify_deserialization (g_variant_new_parsed ("[<[{'one', <1>},{'two', <2>}]>]"),
		NULL,
		"<params><param><value><struct>"
		"<member><name>one</name><value><int>1</int></value></member>"
		"<member><name>two</name><value><int>2</int></value></member>"
		"</struct></value></param></params>");
	verify_deserialization (g_variant_new_parsed ("([{'one', 1},{'two', 2}],)"),
		"(a{si})",
		"<params><param><value><struct>"
		"<member><name>one</name><value><int>1</int></value></member>"
		"<member><name>two</name><value><int>2</int></value></member>"
		"</struct></value></param></params>");
	verify_deserialization (g_variant_new_parsed ("[<int64 1434161309>]"),
		NULL,
		"<params>"
		"<param><value><dateTime.iso8601>2015-06-12T22:08:29-04:00</dateTime.iso8601></value></param>"
		"</params>");
	verify_deserialization (g_variant_new_parsed ("[<b'bytestring'>]"),
		NULL,
		"<params>"
		"<param><value><base64>Ynl0ZXN0cmluZwA=</base64></value></param>"
		"</params>");
	verify_deserialization (g_variant_new_parsed ("(@o '/path',)"),
		"(o)",
		"<params>"
		"<param><value><string>/path</string></value></param>"
		"</params>");
	verify_deserialization (g_variant_new_parsed ("[<1>]"),
		"av",
		"<params><param><value><int>1</int></value></param></params>");
	verify_deserialization (g_variant_new_parsed ("[<%s>]", "<>&"),
		NULL,
		"<params>"
		"<param><value><string>&lt;&gt;&amp;</string></value></param>"
		"</params>");
	verify_deserialization (g_variant_new_parsed ("(@y 255,)"),
		"(y)",
		"<params>"
		"<param><value><int>255</int></value></param>"
		"</params>");

	verify_deserialization_fail ("(o)",
		"<params>"
		"<param><value><string>not/a/path</string></value></param>"
		"</params>");
	verify_deserialization_fail (NULL,
		"<params>"
		"<param><value><boolean>2</boolean></value></param>"
		"</params>");
	verify_deserialization_fail ("(y)",
		"<params>"
		"<param><value><int>256</int></value></param>"
		"</params>");
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/xmlrpc/variant/serializer", test_serializer);
	g_test_add_func ("/xmlrpc/variant/deserializer", test_deserializer);

	return g_test_run ();
}
