/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2005 Novell, Inc.
 */

#include "test-utils.h"

static void check_ok (gconstpointer data);

static SoupDate *
make_date (const char *strdate)
{
	char *dup;
	SoupDate *date;

	/* We do it this way so that if soup_date_new_from_string()
	 * reads off the end of the string, it will trigger an error
	 * when valgrinding, rather than just reading the start of the
	 * next const string.
	 */
	dup = g_strdup (strdate);
	date = soup_date_new_from_string (dup);
	g_free (dup);
	return date;
}

typedef struct {
	SoupDateFormat format;
	const char *date;
} GoodDate;

static const GoodDate good_dates[] = {
	{ SOUP_DATE_HTTP,            "Sat, 06 Nov 2004 08:09:07 GMT" },
	{ SOUP_DATE_COOKIE,          "Sat, 06-Nov-2004 08:09:07 GMT" },
	{ SOUP_DATE_RFC2822,         "Sat, 6 Nov 2004 08:09:07 -0430" },
	{ SOUP_DATE_ISO8601_COMPACT, "20041106T080907" },
	{ SOUP_DATE_ISO8601_FULL,    "2004-11-06T08:09:07" },
	{ SOUP_DATE_ISO8601_XMLRPC,  "20041106T08:09:07" }
};

static void
check_good (gconstpointer data)
{
	GoodDate *good = (GoodDate *)data;
	SoupDate *date;
	char *strdate2;

	check_ok (good->date);

	date = make_date (good->date);
	strdate2 = soup_date_to_string (date, good->format);
	soup_date_free (date);

	soup_test_assert (strcmp (good->date, strdate2) == 0,
			  "restringification failed: '%s' -> '%s'\n",
			  good->date, strdate2);
	g_free (strdate2);
}

static const char *ok_dates[] = {
	/* rfc1123-date, and broken variants */
	"Sat, 06 Nov 2004 08:09:07 GMT",
	"Sat, 6 Nov 2004 08:09:07 GMT",
	"Sat,  6 Nov 2004 08:09:07 GMT",
	"Sat, 06 Nov 2004 08:09:07",
	"06 Nov 2004 08:09:07 GMT",
	"SAT, 06 NOV 2004 08:09:07 +1000",

	/* rfc850-date, and broken variants */
	"Saturday, 06-Nov-04 08:09:07 GMT",
	"Saturday, 6-Nov-04 08:09:07 GMT",
	"Saturday,  6-Nov-04 08:09:07 GMT",
	"Saturday, 06-Nov-104 08:09:07 GMT",
	"Saturday, 06-Nov-04 08:09:07",
	"06-Nov-04 08:09:07 GMT",

	/* asctime-date, and broken variants */
	"Sat Nov  6 08:09:07 2004",
	"Sat Nov 06 08:09:07 2004",
	"Sat Nov 6 08:09:07 2004",
	"Sat Nov  6 08:09:07 2004 GMT",

	/* ISO 8601 */
	"2004-11-06T08:09:07Z",
	"20041106T08:09:07Z",
	"20041106T08:09:07+00:00",
	"20041106T080907+00:00",

	/* Netscape cookie spec date, and broken variants */
	"Sat, 06-Nov-2004 08:09:07 GMT",
	"Sat, 6-Nov-2004 08:09:07 GMT",
	"Sat,  6-Nov-2004 08:09:07 GMT",
	"Sat, 06-Nov-2004 08:09:07",

	/* Original version of Netscape cookie spec, and broken variants */
	"Sat, 06-Nov-04 08:09:07 GMT",
	"Sat, 6-Nov-04 08:09:07 GMT",
	"Sat,  6-Nov-04 08:09:07 GMT",
	"Sat, 06-Nov-104 08:09:07 GMT",
	"Sat, 06-Nov-04 08:09:07",

	/* Netscape cookie spec example syntax, and broken variants */
	"Saturday, 06-Nov-04 08:09:07 GMT",
	"Saturday, 6-Nov-04 08:09:07 GMT",
	"Saturday,  6-Nov-04 08:09:07 GMT",
	"Saturday, 06-Nov-104 08:09:07 GMT",
	"Saturday, 06-Nov-2004 08:09:07 GMT",
	"Saturday, 6-Nov-2004 08:09:07 GMT",
	"Saturday,  6-Nov-2004 08:09:07 GMT",
	"Saturday, 06-Nov-04 08:09:07",

	/* Miscellaneous broken formats seen on the web */
	"Sat 06-Nov-2004  08:9:07",
	"Saturday, 06-Nov-04 8:9:07 GMT",
	"Sat, 06 Nov 2004 08:09:7 GMT"
};

static void
check_ok (gconstpointer data)
{
	const char *strdate = data;
	SoupDate *date;

	date = make_date (strdate);
	if (!date) {
		g_assert_true (date != NULL);
		return;
	}

	g_assert_cmpint (date->year,   ==, 2004);
	g_assert_cmpint (date->month,  ==, 11);
	g_assert_cmpint (date->day,    ==, 6);
	g_assert_cmpint (date->hour,   ==, 8);
	g_assert_cmpint (date->minute, ==, 9);
	g_assert_cmpint (date->second, ==, 7);
}

#define TIME_T 1099728547L
#define TIME_T_STRING "1099728547"

static void
check_ok_time_t (void)
{
	SoupDate *date;

	date = soup_date_new_from_time_t (TIME_T);

	g_assert_cmpint (date->year,   ==, 2004);
	g_assert_cmpint (date->month,  ==, 11);
	g_assert_cmpint (date->day,    ==, 6);
	g_assert_cmpint (date->hour,   ==, 8);
	g_assert_cmpint (date->minute, ==, 9);
	g_assert_cmpint (date->second, ==, 7);
}

static const char *bad_dates[] = {
	/* broken rfc1123-date */
	", 06 Nov 2004 08:09:07 GMT",
	"Sat, Nov 2004 08:09:07 GMT",
	"Sat, 06 2004 08:09:07 GMT",
	"Sat, 06 Nov 08:09:07 GMT",
	"Sat, 06 Nov 2004 :09:07 GMT",
	"Sat, 06 Nov 2004 09:07 GMT",
	"Sat, 06 Nov 2004 08::07 GMT",
	"Sat, 06 Nov 2004 08:09: GMT",

	/* broken rfc850-date */
	", 06-Nov-04 08:09:07 GMT",
	"Saturday, -Nov-04 08:09:07 GMT",
	"Saturday, Nov-04 08:09:07 GMT",
	"Saturday, 06-04 08:09:07 GMT",
	"Saturday, 06--04 08:09:07 GMT",
	"Saturday, 06-Nov- 08:09:07 GMT",
	"Saturday, 06-Nov 08:09:07 GMT",
	"Saturday, 06-Nov-04 :09:07 GMT",
	"Saturday, 06-Nov-04 09:07 GMT",
	"Saturday, 06-Nov-04 08::07 GMT",
	"Saturday, 06-Nov-04 08:09: GMT",

	/* broken asctime-date */
	"Nov  6 08:09:07 2004",
	"Sat  6 08:09:07 2004",
	"Sat Nov 08:09:07 2004",
	"Sat Nov  6 :09:07 2004",
	"Sat Nov  6 09:07 2004",
	"Sat Nov  6 08::07 2004",
	"Sat Nov  6 08:09: 2004",
	"Sat Nov  6 08:09:07",
	"Sat Nov  6 08:09:07 GMT 2004"
};

static void
check_bad (gconstpointer data)
{
	const char *strdate = data;
	SoupDate *date;

	date = make_date (strdate);
	soup_test_assert (date == NULL,
			  "date parsing succeeded for '%s': %d %d %d - %d %d %d",
			  strdate,
			  date->year, date->month, date->day,
			  date->hour, date->minute, date->second);
	g_clear_pointer (&date, soup_date_free);
}

typedef struct {
	const char *source;
	const char *http, *cookie, *rfc2822, *compact, *full, *xmlrpc;
} DateConversion;

static const DateConversion conversions[] = {
	/* SOUP_DATE_HTTP */
	{ "Sat, 06 Nov 2004 08:09:07 GMT",

	  "Sat, 06 Nov 2004 08:09:07 GMT",
	  "Sat, 06-Nov-2004 08:09:07 GMT",
	  "Sat, 6 Nov 2004 08:09:07 +0000",
	  "20041106T080907Z",
	  "2004-11-06T08:09:07Z",
	  "20041106T08:09:07" },

	/* RFC2822 GMT */
	{ "Sat, 6 Nov 2004 08:09:07 +0000",

	  "Sat, 06 Nov 2004 08:09:07 GMT",
	  "Sat, 06-Nov-2004 08:09:07 GMT",
	  "Sat, 6 Nov 2004 08:09:07 +0000",
	  "20041106T080907Z",
	  "2004-11-06T08:09:07Z",
	  "20041106T08:09:07" },

	/* RFC2822 with positive offset */
	{ "Sat, 6 Nov 2004 08:09:07 +0430",

	  "Sat, 06 Nov 2004 04:39:07 GMT",
	  "Sat, 06-Nov-2004 04:39:07 GMT",
	  "Sat, 6 Nov 2004 08:09:07 +0430",
	  "20041106T080907+0430",
	  "2004-11-06T08:09:07+04:30",
	  "20041106T08:09:07" },

	/* RFC2822 with negative offset */
	{ "Sat, 6 Nov 2004 08:09:07 -0430",

	  "Sat, 06 Nov 2004 12:39:07 GMT",
	  "Sat, 06-Nov-2004 12:39:07 GMT",
	  "Sat, 6 Nov 2004 08:09:07 -0430",
	  "20041106T080907-0430",
	  "2004-11-06T08:09:07-04:30",
	  "20041106T08:09:07" },

	/* RFC2822 floating */
	{ "Sat, 6 Nov 2004 08:09:07 -0000",

	  "Sat, 06 Nov 2004 08:09:07 GMT",
	  "Sat, 06-Nov-2004 08:09:07 GMT",
	  "Sat, 6 Nov 2004 08:09:07 -0000",
	  "20041106T080907",
	  "2004-11-06T08:09:07",
	  "20041106T08:09:07" },

	/* ISO GMT */
	{ "2004-11-06T08:09:07Z",

	  "Sat, 06 Nov 2004 08:09:07 GMT",
	  "Sat, 06-Nov-2004 08:09:07 GMT",
	  "Sat, 6 Nov 2004 08:09:07 +0000",
	  "20041106T080907Z",
	  "2004-11-06T08:09:07Z",
	  "20041106T08:09:07" },

	/* ISO with positive offset */
	{ "2004-11-06T08:09:07+04:30",

	  "Sat, 06 Nov 2004 04:39:07 GMT",
	  "Sat, 06-Nov-2004 04:39:07 GMT",
	  "Sat, 6 Nov 2004 08:09:07 +0430",
	  "20041106T080907+0430",
	  "2004-11-06T08:09:07+04:30",
	  "20041106T08:09:07" },

	/* ISO with negative offset */
	{ "2004-11-06T08:09:07-04:30",

	  "Sat, 06 Nov 2004 12:39:07 GMT",
	  "Sat, 06-Nov-2004 12:39:07 GMT",
	  "Sat, 6 Nov 2004 08:09:07 -0430",
	  "20041106T080907-0430",
	  "2004-11-06T08:09:07-04:30",
	  "20041106T08:09:07" },

	/* ISO floating */
	{ "2004-11-06T08:09:07",

	  "Sat, 06 Nov 2004 08:09:07 GMT",
	  "Sat, 06-Nov-2004 08:09:07 GMT",
	  "Sat, 6 Nov 2004 08:09:07 -0000",
	  "20041106T080907",
	  "2004-11-06T08:09:07",
	  "20041106T08:09:07" }
};

static void
check_conversion (gconstpointer data)
{
	const DateConversion *conv = data;
	SoupDate *date;
	char *str;

	date = make_date (conv->source);
	if (!date) {
		soup_test_assert (FALSE, "date parsing failed for '%s'.", conv->source);
		return;
	}

	str = soup_date_to_string (date, SOUP_DATE_HTTP);
	g_assert_cmpstr (str, ==, conv->http);
	g_free (str);

	str = soup_date_to_string (date, SOUP_DATE_COOKIE);
	g_assert_cmpstr (str, ==, conv->cookie);
	g_free (str);

	str = soup_date_to_string (date, SOUP_DATE_RFC2822);
	g_assert_cmpstr (str, ==, conv->rfc2822);
	g_free (str);

	str = soup_date_to_string (date, SOUP_DATE_ISO8601_COMPACT);
	g_assert_cmpstr (str, ==, conv->compact);
	g_free (str);

	str = soup_date_to_string (date, SOUP_DATE_ISO8601_FULL);
	g_assert_cmpstr (str, ==, conv->full);
	g_free (str);

	str = soup_date_to_string (date, SOUP_DATE_ISO8601_XMLRPC);
	g_assert_cmpstr (str, ==, conv->xmlrpc);
	g_free (str);

	soup_date_free (date);
}

int
main (int argc, char **argv)
{
	int i, ret;
	char *path;

	test_init (argc, argv, NULL);

	for (i = 0; i < G_N_ELEMENTS (good_dates); i++) {
		path = g_strdup_printf ("/date/good/%s", good_dates[i].date);
		g_test_add_data_func (path, &good_dates[i], check_good);
		g_free (path);
	}

	for (i = 0; i < G_N_ELEMENTS (ok_dates); i++) {
		path = g_strdup_printf ("/date/ok/%s", ok_dates[i]);
		g_test_add_data_func (path, ok_dates[i], check_ok);
		g_free (path);
	}
	g_test_add_func ("/date/ok/" TIME_T_STRING, check_ok_time_t);

	for (i = 0; i < G_N_ELEMENTS (bad_dates); i++) {
		path = g_strdup_printf ("/date/bad/%s", bad_dates[i]);
		g_test_add_data_func (path, bad_dates[i], check_bad);
		g_free (path);
	}

	for (i = 0; i < G_N_ELEMENTS (conversions); i++) {
		path = g_strdup_printf ("/date/conversions/%s", conversions[i].source);
		g_test_add_data_func (path, &conversions[i], check_conversion);
		g_free (path);
	}

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
