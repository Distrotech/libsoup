/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2012 Igalia S.L.
 */

#include "test-utils.h"

/* From http://publicsuffix.org/list/test.txt */
static struct {
	const char *hostname;
	const char *result;
	SoupTLDError error;
} tld_tests[] = {
	/* NULL input. Not checked here because the API requires a valid hostname. */
	/* { NULL, NULL }, */
	/* Mixed case. Not checked because the API requires a valid hostname. */
	/* { "COM", NULL }, */
	/* { "example.COM", "example.com" }, */
	/* { "WwW.example.COM", "example.com" }, */
	/* Leading dot. */
	{ ".com", NULL, SOUP_TLD_ERROR_INVALID_HOSTNAME },
	{ ".example", NULL, SOUP_TLD_ERROR_INVALID_HOSTNAME },
	{ ".example.com", NULL, SOUP_TLD_ERROR_INVALID_HOSTNAME },
	{ ".example.example", NULL, SOUP_TLD_ERROR_INVALID_HOSTNAME },
	/* TLD with only 1 rule. */
	{ "biz", NULL, SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS },
	{ "domain.biz", "domain.biz", -1 },
	{ "b.domain.biz", "domain.biz", -1 },
	{ "a.b.domain.biz", "domain.biz", -1 },
	/* TLD with some 2-level rules. */
	{ "com", NULL, SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS },
	{ "example.com", "example.com", -1 },
	{ "b.example.com", "example.com", -1 },
	{ "a.b.example.com", "example.com", -1 },
	{ "uk.com", NULL, SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS },
	{ "example.uk.com", "example.uk.com", -1 },
	{ "b.example.uk.com", "example.uk.com", -1 },
	{ "a.b.example.uk.com", "example.uk.com", -1 },
	{ "test.ac", "test.ac", -1 },
	/* TLD with only 1 (wildcard) rule. */
	{ "cy", NULL, SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS },
	{ "c.cy", NULL, SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS },
	{ "b.c.cy", "b.c.cy", -1 },
	{ "a.b.c.cy", "b.c.cy", -1 },
	/* More complex TLD. */
	{ "jp", NULL, SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS },
	{ "test.jp", "test.jp", -1 },
	{ "www.test.jp", "test.jp", -1 },
	{ "ac.jp", NULL, SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS },
	{ "test.ac.jp", "test.ac.jp", -1 },
	{ "www.test.ac.jp", "test.ac.jp", -1 },
	{ "kyoto.jp", NULL, SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS },
	{ "minami.kyoto.jp", NULL, SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS },
	{ "b.minami.kyoto.jp", "b.minami.kyoto.jp", -1 },
	{ "a.b.minami.kyoto.jp", "b.minami.kyoto.jp", -1 },
	{ "pref.kyoto.jp", "pref.kyoto.jp", -1 },
	{ "www.pref.kyoto.jp", "pref.kyoto.jp", -1 },
	{ "city.kyoto.jp", "city.kyoto.jp", -1 },
	{ "www.city.kyoto.jp", "city.kyoto.jp", -1 },
	/* TLD with a wildcard rule and exceptions. */
	{ "om", NULL, SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS },
	{ "test.om", NULL, SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS },
	{ "b.test.om", "b.test.om", -1 },
	{ "a.b.test.om", "b.test.om", -1 },
	{ "songfest.om", "songfest.om", -1 },
	{ "www.songfest.om", "songfest.om", -1 },
	/* US K12. */
	{ "us", NULL, SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS },
	{ "test.us", "test.us", -1 },
	{ "www.test.us", "test.us", -1 },
	{ "ak.us", NULL, SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS },
	{ "test.ak.us", "test.ak.us", -1 },
	{ "www.test.ak.us", "test.ak.us", -1 },
	{ "k12.ak.us", NULL, SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS },
	{ "test.k12.ak.us", "test.k12.ak.us", -1 },
	{ "www.test.k12.ak.us", "test.k12.ak.us", -1 },
	/* This is not in http://publicsuffix.org/list/test.txt but we want to check it anyway. */
	{ "co.uk", NULL, SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS },
	/* The original list does not include non-ASCII tests. Let's add a couple. */
	{ "公司.cn", NULL, SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS },
	{ "a.b.åfjord.no", "b.åfjord.no", -1 }
},

/* Non Internet TLDs have NULL as expected result
 */
non_inet_tld_tests[] = {
	/* Unlisted TLD.*/
	{ "example", NULL },
	{ "example.example", NULL },
	{ "b.example.example", NULL },
	{ "a.b.example.example", NULL },
	/* Listed, but non-Internet, TLD. */
	{ "local", NULL },
	{ "example.local", NULL },
	{ "b.example.local", NULL },
	{ "a.b.example.local", NULL }
};

static void
do_inet_tests (void)
{
	int i;

	for (i = 0; i < G_N_ELEMENTS (tld_tests); i++) {
		GError *error = NULL;
		gboolean is_public;
		const char *base_domain;

		debug_printf (1, "Testing %s\n", tld_tests[i].hostname);

		is_public = soup_tld_domain_is_public_suffix (tld_tests[i].hostname);
		base_domain = soup_tld_get_base_domain (tld_tests[i].hostname, &error);

		if (base_domain) {
			g_assert_no_error (error);
			g_assert_false (is_public);
			g_assert_cmpstr (base_domain, ==, tld_tests[i].result);
		} else {
			g_assert_null (tld_tests[i].result);
			g_assert_error (error, SOUP_TLD_ERROR, tld_tests[i].error);
			g_clear_error (&error);
		}
	}
}

static void
do_non_inet_tests (void)
{
	int i;

	for (i = 0; i < G_N_ELEMENTS (non_inet_tld_tests); i++) {
		gboolean is_public;
		const char *base_domain;

		debug_printf (1, "Testing %s: ", non_inet_tld_tests[i].hostname);

		is_public = soup_tld_domain_is_public_suffix (non_inet_tld_tests[i].hostname);
		base_domain = soup_tld_get_base_domain (non_inet_tld_tests[i].hostname, NULL);

		g_assert_false (is_public);
		g_assert_null (base_domain);
	}
}

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	g_test_add_func ("/tld/inet", do_inet_tests);
	g_test_add_func ("/tld/non-inet", do_non_inet_tests);

	ret = g_test_run ();

	test_cleanup ();

	return ret;
}
