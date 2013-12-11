/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

static struct {
	const char *uri_string, *result;
	const SoupURI bits;
} abs_tests[] = {
	{ "foo:", "foo:",
	  { "foo", NULL, NULL, NULL, 0, "", NULL, NULL } },
	{ "file:/dev/null", "file:/dev/null",
	  { "file", NULL, NULL, NULL, 0, "/dev/null", NULL, NULL } },
	{ "file:///dev/null", "file:///dev/null",
	  { "file", NULL, NULL, "", 0, "/dev/null", NULL, NULL } },
	{ "ftp://user@host/path", "ftp://user@host/path",
	  { "ftp", "user", NULL, "host", 21, "/path", NULL, NULL } },
	{ "ftp://user@host:9999/path", "ftp://user@host:9999/path",
	  { "ftp", "user", NULL, "host", 9999, "/path", NULL, NULL } },
	{ "ftp://user:password@host/path", "ftp://user@host/path",
	  { "ftp", "user", "password", "host", 21, "/path", NULL, NULL } },
	{ "ftp://user:password@host:9999/path", "ftp://user@host:9999/path",
	  { "ftp", "user", "password", "host", 9999, "/path", NULL, NULL } },
	{ "ftp://user:password@host", "ftp://user@host",
	  { "ftp", "user", "password", "host", 21, "", NULL, NULL } },
	{ "http://us%65r@host", "http://user@host/",
	  { "http", "user", NULL, "host", 80, "/", NULL, NULL } },
	{ "http://us%40r@host", "http://us%40r@host/",
	  { "http", "us\x40r", NULL, "host", 80, "/", NULL, NULL } },
	{ "http://us%3ar@host", "http://us%3Ar@host/",
	  { "http", "us\x3ar", NULL, "host", 80, "/", NULL, NULL } },
	{ "http://us%2fr@host", "http://us%2Fr@host/",
	  { "http", "us\x2fr", NULL, "host", 80, "/", NULL, NULL } },
	{ "http://us%3fr@host", "http://us%3Fr@host/",
	  { "http", "us\x3fr", NULL, "host", 80, "/", NULL, NULL } },
	{ "http://host?query", "http://host/?query",
	  { "http", NULL, NULL, "host", 80, "/", "query", NULL } },
	{ "http://host/path?query=http%3A%2F%2Fhost%2Fpath%3Fchildparam%3Dchildvalue&param=value",
	  "http://host/path?query=http%3A%2F%2Fhost%2Fpath%3Fchildparam%3Dchildvalue&param=value",
	  { "http", NULL, NULL, "host", 80, "/path", "query=http%3A%2F%2Fhost%2Fpath%3Fchildparam%3Dchildvalue&param=value", NULL } },
	{ "http://control-chars/%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F%7F",
	  "http://control-chars/%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F%7F",
	  { "http", NULL, NULL, "control-chars", 80, "/%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F%7F", NULL, NULL } },
	{ "http://space/%20",
	  "http://space/%20",
	  { "http", NULL, NULL, "space", 80, "/%20", NULL, NULL } },
	{ "http://delims/%3C%3E%23%25%22",
	  "http://delims/%3C%3E%23%25%22",
	  { "http", NULL, NULL, "delims", 80, "/%3C%3E%23%25%22", NULL, NULL } },
	{ "http://unwise-chars/%7B%7D%7C%5C%5E%5B%5D%60",
	  "http://unwise-chars/%7B%7D%7C%5C%5E%5B%5D%60",
	  { "http", NULL, NULL, "unwise-chars", 80, "/%7B%7D%7C%5C%5E%5B%5D%60", NULL, NULL } },

	/* From RFC 2732 */
	{ "http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80/index.html",
	  "http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]/index.html",
	  { "http", NULL, NULL, "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210", 80, "/index.html", NULL, NULL } },
	{ "http://[1080:0:0:0:8:800:200C:417A]/index.html",
	  "http://[1080:0:0:0:8:800:200C:417A]/index.html",
	  { "http", NULL, NULL, "1080:0:0:0:8:800:200C:417A", 80, "/index.html", NULL, NULL } },
	{ "http://[3ffe:2a00:100:7031::1]",
	  "http://[3ffe:2a00:100:7031::1]/",
	  { "http", NULL, NULL, "3ffe:2a00:100:7031::1", 80, "/", NULL, NULL } },
	{ "http://[1080::8:800:200C:417A]/foo",
	  "http://[1080::8:800:200C:417A]/foo",
	  { "http", NULL, NULL, "1080::8:800:200C:417A", 80, "/foo", NULL, NULL } },
	{ "http://[::192.9.5.5]/ipng",
	  "http://[::192.9.5.5]/ipng",
	  { "http", NULL, NULL, "::192.9.5.5", 80, "/ipng", NULL, NULL } },
	{ "http://[::FFFF:129.144.52.38]:80/index.html",
	  "http://[::FFFF:129.144.52.38]/index.html",
	  { "http", NULL, NULL, "::FFFF:129.144.52.38", 80, "/index.html", NULL, NULL } },
	{ "http://[2010:836B:4179::836B:4179]",
	  "http://[2010:836B:4179::836B:4179]/",
	  { "http", NULL, NULL, "2010:836B:4179::836B:4179", 80, "/", NULL, NULL } },

	/* Try to recover certain kinds of invalid URIs */
	{ "http://host/path with spaces",
	  "http://host/path%20with%20spaces",
	  { "http", NULL, NULL, "host", 80, "/path%20with%20spaces", NULL, NULL } },
	{ "  http://host/path", "http://host/path",
	  { "http", NULL, NULL, "host", 80, "/path", NULL, NULL } },
	{ "http://host/path  ", "http://host/path",
	  { "http", NULL, NULL, "host", 80, "/path", NULL, NULL } },
	{ "http://host  ", "http://host/",
	  { "http", NULL, NULL, "host", 80, "/", NULL, NULL } },
	{ "http://host:999  ", "http://host:999/",
	  { "http", NULL, NULL, "host", 999, "/", NULL, NULL } },
	{ "http://host/pa\nth", "http://host/path",
	  { "http", NULL, NULL, "host", 80, "/path", NULL, NULL } },
	{ "http:\r\n//host/path", "http://host/path",
	  { "http", NULL, NULL, "host", 80, "/path", NULL, NULL } },
	{ "http://\thost/path", "http://host/path",
	  { "http", NULL, NULL, "host", 80, "/path", NULL, NULL } },

	/* Bug 594405; 0-length is different from not-present */
	{ "http://host/path?", "http://host/path?",
	  { "http", NULL, NULL, "host", 80, "/path", "", NULL } },
	{ "http://host/path#", "http://host/path#",
	  { "http", NULL, NULL, "host", 80, "/path", NULL, "" } },

	/* Bug 590524; ignore badly-%-encoding */
	{ "http://host/path%", "http://host/path%",
	  { "http", NULL, NULL, "host", 80, "/path%", NULL, NULL } },
	{ "http://h%ost/path", "http://h%25ost/path",
	  { "http", NULL, NULL, "h%ost", 80, "/path", NULL, NULL } },
	{ "http://host/path%%", "http://host/path%%",
	  { "http", NULL, NULL, "host", 80, "/path%%", NULL, NULL } },
	{ "http://host/path%%%", "http://host/path%%%",
	  { "http", NULL, NULL, "host", 80, "/path%%%", NULL, NULL } },
	{ "http://host/path%/x/", "http://host/path%/x/",
	  { "http", NULL, NULL, "host", 80, "/path%/x/", NULL, NULL } },
	{ "http://host/path%0x/", "http://host/path%0x/",
	  { "http", NULL, NULL, "host", 80, "/path%0x/", NULL, NULL } },
	{ "http://host/path%ax", "http://host/path%ax",
	  { "http", NULL, NULL, "host", 80, "/path%ax", NULL, NULL } },

	/* Bug 662806; %-encode non-ASCII characters */
	{ "http://host/p\xc3\xa4th/", "http://host/p%C3%A4th/",
	  { "http", NULL, NULL, "host", 80, "/p%C3%A4th/", NULL, NULL } },

	{ "HTTP:////////////////", "http:////////////////",
	  { "http", NULL, NULL, "", 80, "//////////////", NULL, NULL } },

	{ "http://@host", "http://@host/",
	  { "http", "", NULL, "host", 80, "/", NULL, NULL } },
	{ "http://:@host", "http://@host/",
	  { "http", "", "", "host", 80, "/", NULL, NULL } },

	{ "http://host/keep%00nuls", "http://host/keep%00nuls",
	  { "http", NULL, NULL, "host", 80, "/keep%00nuls", NULL, NULL } },

	/* Bug 703776; scheme parsing */
	{ "foo0://host/path", "foo0://host/path",
	  { "foo0", NULL, NULL, "host", 0, "/path", NULL, NULL } },
	{ "f0.o://host/path", "f0.o://host/path",
	  { "f0.o", NULL, NULL, "host", 0, "/path", NULL, NULL } },
	{ "http++://host/path", "http++://host/path",
	  { "http++", NULL, NULL, "host", 0, "/path", NULL, NULL } },
	{ "http-ish://host/path", "http-ish://host/path",
	  { "http-ish", NULL, NULL, "host", 0, "/path", NULL, NULL } },
	{ "99http://host/path", NULL,
	  { NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL } },
	{ ".http://host/path", NULL,
	  { NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL } },
	{ "+http://host/path", NULL,
	  { NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL } },

	/* IPv6 scope ID parsing (both correct and incorrect) */
	{ "http://[fe80::dead:beef%em1]/", "http://[fe80::dead:beef%25em1]/",
	  { "http", NULL, NULL, "fe80::dead:beef%em1", 80, "/", NULL, NULL } },
	{ "http://[fe80::dead:beef%25em1]/", "http://[fe80::dead:beef%25em1]/",
	  { "http", NULL, NULL, "fe80::dead:beef%em1", 80, "/", NULL, NULL } },
	{ "http://[fe80::dead:beef%10]/", "http://[fe80::dead:beef%2510]/",
	  { "http", NULL, NULL, "fe80::dead:beef%10", 80, "/", NULL, NULL } }
};
static int num_abs_tests = G_N_ELEMENTS(abs_tests);

/* From RFC 3986. */
static const char *base = "http://a/b/c/d;p?q";
static struct {
	const char *uri_string, *result;
	const SoupURI bits;
} rel_tests[] = {
	{ "g:h", "g:h",
	  { "g", NULL, NULL, NULL, 0, "h", NULL, NULL } },
	{ "g", "http://a/b/c/g",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", NULL, NULL } },
	{ "./g", "http://a/b/c/g",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", NULL, NULL } },
	{ "g/", "http://a/b/c/g/",
	  { "http", NULL, NULL, "a", 80, "/b/c/g/", NULL, NULL } },
	{ "/g", "http://a/g",
	  { "http", NULL, NULL, "a", 80, "/g", NULL, NULL } },
	{ "//g", "http://g/",
	  { "http", NULL, NULL, "g", 80, "/", NULL, NULL } },
	{ "?y", "http://a/b/c/d;p?y",
	  { "http", NULL, NULL, "a", 80, "/b/c/d;p", "y", NULL } },
	{ "g?y", "http://a/b/c/g?y",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", "y", NULL } },
	{ "#s", "http://a/b/c/d;p?q#s",
	  { "http", NULL, NULL, "a", 80, "/b/c/d;p", "q", "s" } },
	{ "g#s", "http://a/b/c/g#s",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", NULL, "s" } },
	{ "g?y#s", "http://a/b/c/g?y#s",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", "y", "s" } },
	{ ";x", "http://a/b/c/;x",
	  { "http", NULL, NULL, "a", 80, "/b/c/;x", NULL, NULL } },
	{ "g;x", "http://a/b/c/g;x",
	  { "http", NULL, NULL, "a", 80, "/b/c/g;x", NULL, NULL } },
	{ "g;x?y#s", "http://a/b/c/g;x?y#s",
	  { "http", NULL, NULL, "a", 80, "/b/c/g;x", "y", "s" } },
	{ ".", "http://a/b/c/",
	  { "http", NULL, NULL, "a", 80, "/b/c/", NULL, NULL } },
	{ "./", "http://a/b/c/",
	  { "http", NULL, NULL, "a", 80, "/b/c/", NULL, NULL } },
	{ "..", "http://a/b/",
	  { "http", NULL, NULL, "a", 80, "/b/", NULL, NULL } },
	{ "../", "http://a/b/",
	  { "http", NULL, NULL, "a", 80, "/b/", NULL, NULL } },
	{ "../g", "http://a/b/g",
	  { "http", NULL, NULL, "a", 80, "/b/g", NULL, NULL } },
	{ "../..", "http://a/",
	  { "http", NULL, NULL, "a", 80, "/", NULL, NULL } },
	{ "../../", "http://a/",
	  { "http", NULL, NULL, "a", 80, "/", NULL, NULL } },
	{ "../../g", "http://a/g",
	  { "http", NULL, NULL, "a", 80, "/g", NULL, NULL } },
	{ "", "http://a/b/c/d;p?q",
	  { "http", NULL, NULL, "a", 80, "/b/c/d;p", "q", NULL } },
	{ "../../../g", "http://a/g",
	  { "http", NULL, NULL, "a", 80, "/g", NULL, NULL } },
	{ "../../../../g", "http://a/g",
	  { "http", NULL, NULL, "a", 80, "/g", NULL, NULL } },
	{ "/./g", "http://a/g",
	  { "http", NULL, NULL, "a", 80, "/g", NULL, NULL } },
	{ "/../g", "http://a/g",
	  { "http", NULL, NULL, "a", 80, "/g", NULL, NULL } },
	{ "g.", "http://a/b/c/g.",
	  { "http", NULL, NULL, "a", 80, "/b/c/g.", NULL, NULL } },
	{ ".g", "http://a/b/c/.g",
	  { "http", NULL, NULL, "a", 80, "/b/c/.g", NULL, NULL } },
	{ "g..", "http://a/b/c/g..",
	  { "http", NULL, NULL, "a", 80, "/b/c/g..", NULL, NULL } },
	{ "..g", "http://a/b/c/..g",
	  { "http", NULL, NULL, "a", 80, "/b/c/..g", NULL, NULL } },
	{ "./../g", "http://a/b/g",
	  { "http", NULL, NULL, "a", 80, "/b/g", NULL, NULL } },
	{ "./g/.", "http://a/b/c/g/",
	  { "http", NULL, NULL, "a", 80, "/b/c/g/", NULL, NULL } },
	{ "g/./h", "http://a/b/c/g/h",
	  { "http", NULL, NULL, "a", 80, "/b/c/g/h", NULL, NULL } },
	{ "g/../h", "http://a/b/c/h",
	  { "http", NULL, NULL, "a", 80, "/b/c/h", NULL, NULL } },
	{ "g;x=1/./y", "http://a/b/c/g;x=1/y",
	  { "http", NULL, NULL, "a", 80, "/b/c/g;x=1/y", NULL, NULL } },
	{ "g;x=1/../y", "http://a/b/c/y",
	  { "http", NULL, NULL, "a", 80, "/b/c/y", NULL, NULL } },
	{ "g?y/./x", "http://a/b/c/g?y/./x",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", "y/./x", NULL } },
	{ "g?y/../x", "http://a/b/c/g?y/../x",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", "y/../x", NULL } },
	{ "g#s/./x", "http://a/b/c/g#s/./x",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", NULL, "s/./x" } },
	{ "g#s/../x", "http://a/b/c/g#s/../x",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", NULL, "s/../x" } },

	/* RFC 3986 notes that some old parsers will parse this as
	 * a relative URL ("http://a/b/c/g"), but it should be
	 * interpreted as absolute. libsoup should parse it
	 * correctly as being absolute, but then reject it since it's
	 * an http URL with no host.
	 */
	{ "http:g", NULL, { NULL } }
};
static int num_rel_tests = G_N_ELEMENTS(rel_tests);

static struct {
	const char *one, *two;
} eq_tests[] = {
	{ "example://a/b/c/%7Bfoo%7D", "eXAMPLE://a/./b/../b/%63/%7Bfoo%7D" },
	{ "http://example.com", "http://example.com/" },
	/* From RFC 2616 */
	{ "http://abc.com:80/~smith/home.html", "http://abc.com:80/~smith/home.html" },
	{ "http://abc.com:80/~smith/home.html", "http://ABC.com/%7Esmith/home.html" },
	{ "http://abc.com:80/~smith/home.html", "http://ABC.com:/%7esmith/home.html" },
};
static int num_eq_tests = G_N_ELEMENTS(eq_tests);

static void
do_uri (SoupURI *base_uri, const char *base_str,
	const char *in_uri, const char *out_uri,
	const SoupURI *bits)
{
	SoupURI *uri;
	char *uri_string;

	if (base_uri) {
		debug_printf (1, "<%s> + <%s> = <%s>\n", base_str, in_uri,
			      out_uri ? out_uri : "ERR");
		uri = soup_uri_new_with_base (base_uri, in_uri);
	} else {
		debug_printf (1, "<%s> => <%s>\n", in_uri,
			      out_uri ? out_uri : "ERR");
		uri = soup_uri_new (in_uri);
	}

	if (!uri) {
		g_assert_null (out_uri);
		return;
	}

	if (bits != NULL) {
		g_assert_cmpstr (uri->scheme, ==, bits->scheme);
		g_assert_cmpstr (uri->user, ==, bits->user);
		g_assert_cmpstr (uri->password, ==, bits->password);
		g_assert_cmpstr (uri->host, ==, bits->host);
		g_assert_cmpuint (uri->port, ==, bits->port);
		g_assert_cmpstr (uri->path, ==, bits->path);
		g_assert_cmpstr (uri->query, ==, bits->query);
		g_assert_cmpstr (uri->fragment, ==, bits->fragment);
	}

	uri_string = soup_uri_to_string (uri, FALSE);
	soup_uri_free (uri);

	g_assert_cmpstr (uri_string, ==, out_uri);
	g_free (uri_string);
}

static void
do_absolute_uri_tests (void)
{
	int i;

	for (i = 0; i < num_abs_tests; i++) {
		do_uri (NULL, NULL, abs_tests[i].uri_string,
			abs_tests[i].result, &abs_tests[i].bits);
	}
}

static void
do_relative_uri_tests (void)
{
	SoupURI *base_uri;
	char *uri_string;
	int i;

	base_uri = soup_uri_new (base);
	if (!base_uri) {
		g_printerr ("Could not parse %s!\n", base);
		exit (1);
	}

	uri_string = soup_uri_to_string (base_uri, FALSE);
	g_assert_cmpstr (uri_string, ==, base);
	g_free (uri_string);

	for (i = 0; i < num_rel_tests; i++) {
		do_uri (base_uri, base, rel_tests[i].uri_string,
			rel_tests[i].result, &rel_tests[i].bits);
	}
	soup_uri_free (base_uri);
}

static void
do_equality_tests (void)
{
	SoupURI *uri1, *uri2;
	int i;

	for (i = 0; i < num_eq_tests; i++) {
		uri1 = soup_uri_new (eq_tests[i].one);
		uri2 = soup_uri_new (eq_tests[i].two);

		debug_printf (1, "<%s> == <%s>\n", eq_tests[i].one, eq_tests[i].two);
		g_assert_true (soup_uri_equal (uri1, uri2));

		soup_uri_free (uri1);
		soup_uri_free (uri2);
	}
}

static void
do_soup_uri_null_tests (void)
{
	SoupURI *uri, *uri2;
	char *uri_string;

	uri = soup_uri_new (NULL);
	g_assert_false (SOUP_URI_IS_VALID (uri));
	g_assert_false (SOUP_URI_VALID_FOR_HTTP (uri));

	/* This implicitly also verifies that none of these methods g_warn */
	g_assert_null (soup_uri_get_scheme (uri));
	g_assert_null (soup_uri_get_user (uri));
	g_assert_null (soup_uri_get_password (uri));
	g_assert_null (soup_uri_get_host (uri));
	g_assert_cmpint (soup_uri_get_port (uri), ==, 0);
	g_assert_null (soup_uri_get_path (uri));
	g_assert_null (soup_uri_get_query (uri));
	g_assert_null (soup_uri_get_fragment (uri));

	g_test_expect_message ("libsoup", G_LOG_LEVEL_CRITICAL,
			       "*base == NULL*");
	uri2 = soup_uri_new_with_base (uri, "/path");
	g_test_assert_expected_messages ();
	g_assert_null (uri2);

	g_test_expect_message ("libsoup", G_LOG_LEVEL_WARNING,
			       "*SOUP_URI_IS_VALID*");
	uri_string = soup_uri_to_string (uri, FALSE);
	g_test_assert_expected_messages ();
	g_assert_cmpstr (uri_string, ==, "");
	g_free (uri_string);

	soup_uri_set_scheme (uri, SOUP_URI_SCHEME_HTTP);
	g_assert_false (SOUP_URI_IS_VALID (uri));
	g_assert_false (SOUP_URI_VALID_FOR_HTTP (uri));

	g_test_expect_message ("libsoup", G_LOG_LEVEL_WARNING,
			       "*SOUP_URI_IS_VALID*");
	uri_string = soup_uri_to_string (uri, FALSE);
	g_test_assert_expected_messages ();
	g_assert_cmpstr (uri_string, ==, "http:");
	g_free (uri_string);

	soup_uri_set_host (uri, "localhost");
	g_assert_false (SOUP_URI_IS_VALID (uri));
	g_assert_false (SOUP_URI_VALID_FOR_HTTP (uri));

	g_test_expect_message ("libsoup", G_LOG_LEVEL_WARNING,
			       "*SOUP_URI_IS_VALID*");
	uri_string = soup_uri_to_string (uri, FALSE);
	g_test_assert_expected_messages ();
	g_assert_cmpstr (uri_string, ==, "http://localhost/");
	g_free (uri_string);

	g_test_expect_message ("libsoup", G_LOG_LEVEL_WARNING,
			       "*SOUP_URI_IS_VALID*");
	uri2 = soup_uri_new_with_base (uri, "/path");
	g_test_assert_expected_messages ();
	g_assert_true (uri2 != NULL);

	if (uri2) {
		uri_string = soup_uri_to_string (uri2, FALSE);
		g_assert_cmpstr (uri_string, ==, "http://localhost/path");
		g_free (uri_string);
		soup_uri_free (uri2);
	}

	g_test_expect_message ("libsoup", G_LOG_LEVEL_WARNING,
			       "*path != NULL*");
	soup_uri_set_path (uri, NULL);
	g_test_assert_expected_messages ();
	g_assert_cmpstr (uri->path, ==, "");

	uri_string = soup_uri_to_string (uri, FALSE);
	g_assert_cmpstr (uri_string, ==, "http://localhost/");
	g_free (uri_string);

	g_assert_true (SOUP_URI_IS_VALID (uri));
	g_assert_true (SOUP_URI_VALID_FOR_HTTP (uri));

	soup_uri_free (uri);
}

static struct {
	const char *uri_string, *unescape_extra, *result;
} normalization_tests[] = {
	{ "fo%6fbar",         NULL, "foobar" },
	{ "foo%2fbar",        NULL, "foo%2fbar" },
	{ "foo%2Fbar",        NULL, "foo%2Fbar" },
	{ "foo%2fbar",        "/",  "foo/bar" },
	{ "foo bar",          NULL, "foo%20bar" },
	{ "foo bar",          " ",  "foo bar" },
	{ "fo\xc3\xb6" "bar", NULL, "fo%C3%B6bar" },
	{ "fo\xc3\xb6 bar",   " ",  "fo%C3%B6 bar" }
};
static int num_normalization_tests = G_N_ELEMENTS (normalization_tests);

static void
do_normalization_tests (void)
{
	char *normalized;
	int i;

	for (i = 0; i < num_normalization_tests; i++) {
		if (normalization_tests[i].unescape_extra) {
			debug_printf (1, "<%s> unescaping <%s> => <%s>\n",
				      normalization_tests[i].uri_string,
				      normalization_tests[i].unescape_extra,
				      normalization_tests[i].result);
		} else {
			debug_printf (1, "<%s> => <%s>\n",
				      normalization_tests[i].uri_string,
				      normalization_tests[i].result);
		}

		normalized = soup_uri_normalize (normalization_tests[i].uri_string,
						 normalization_tests[i].unescape_extra);
		g_assert_cmpstr (normalized, ==, normalization_tests[i].result);
		g_free (normalized);
	}
}

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	g_test_add_func ("/uri/absolute", do_absolute_uri_tests);
	g_test_add_func ("/uri/relative", do_relative_uri_tests);
	g_test_add_func ("/uri/equality", do_equality_tests);
	g_test_add_func ("/uri/null", do_soup_uri_null_tests);
	g_test_add_func ("/uri/normalization", do_normalization_tests);

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
