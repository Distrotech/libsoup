/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>

#define LIBSOUP_USE_UNSTABLE_REQUEST_API

#include "libsoup/soup.h"
#include "libsoup/soup-requester.h"

void test_init    (int argc, char **argv, GOptionEntry *entries);
void test_cleanup (void);

extern int debug_level;
extern gboolean tls_available;
void debug_printf (int level, const char *format, ...) G_GNUC_PRINTF (2, 3);

#ifdef HAVE_APACHE
void apache_init    (void);
void apache_cleanup (void);
#endif

typedef enum {
	SOUP_TEST_REQUEST_NONE = 0,
	SOUP_TEST_REQUEST_CANCEL_MESSAGE = (1 << 0),
	SOUP_TEST_REQUEST_CANCEL_CANCELLABLE = (1 << 1),
	SOUP_TEST_REQUEST_CANCEL_SOON = (1 << 2),
	SOUP_TEST_REQUEST_CANCEL_IMMEDIATE = (1 << 3),
	SOUP_TEST_REQUEST_CANCEL_PREEMPTIVE = (1 << 4),
	SOUP_TEST_REQUEST_CANCEL_AFTER_SEND_FINISH = (1 << 5),
} SoupTestRequestFlags;

SoupSession *soup_test_session_new         (GType type, ...);
void         soup_test_session_abort_unref (SoupSession *session);

SoupServer  *soup_test_server_new        (gboolean in_own_thread);
SoupServer  *soup_test_server_new_ssl    (gboolean in_own_thread);
void         soup_test_server_quit_unref (SoupServer *server);

GInputStream *soup_test_request_send         (SoupRequest  *req,
					      GCancellable *cancellable,
					      guint         flags,
					      GError       **error);
gboolean      soup_test_request_read_all     (SoupRequest   *req,
					      GInputStream  *stream,
					      GCancellable  *cancellable,
					      GError       **error);
gboolean      soup_test_request_close_stream (SoupRequest   *req,
					      GInputStream  *stream,
					      GCancellable  *cancellable,
					      GError       **error);

void        soup_test_register_resources (void);
SoupBuffer *soup_test_load_resource      (const char  *name,
					  GError     **error);

SoupBuffer *soup_test_get_index          (void);

#ifdef G_HAVE_ISO_VARARGS
#define soup_test_assert(expr, ...)				\
G_STMT_START {								\
	char *_message;							\
	if (G_UNLIKELY (!(expr))) {					\
		_message = g_strdup_printf (__VA_ARGS__);		\
		g_assertion_message (G_LOG_DOMAIN,			\
				     __FILE__, __LINE__, G_STRFUNC,	\
				     _message);				\
		g_free (_message);					\
	}								\
} G_STMT_END
#else
void soup_test_assert (gboolean expr, const char *fmt, ...);
#endif

#define soup_test_assert_message_status(msg, status)			\
G_STMT_START {								\
	SoupMessage *_msg = (msg);					\
	guint _status = (status);					\
	char *_message;							\
									\
	if (G_UNLIKELY (_msg->status_code != _status)) {		\
		_message = g_strdup_printf ("Unexpected status %d %s (expected %d %s)", \
					    _msg->status_code, _msg->reason_phrase,     \
					    _status, soup_status_get_phrase (_status)); \
		g_assertion_message (G_LOG_DOMAIN,			\
				     __FILE__, __LINE__, G_STRFUNC,	\
				     _message);				\
		g_free (_message);					\
	}								\
} G_STMT_END

#define soup_assert_cmpmem(s1, l1, s2, l2)				\
G_STMT_START {								\
	int __l1 = l1, __l2 = l2;					\
	gconstpointer __s1 = s1, __s2 = s2;				\
	if (G_UNLIKELY ((__l1) != (__l2))) {				\
		g_assertion_message_cmpnum (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, \
					    "len(" #s1 ") == len(" #s2 ")", __l1, "==", __l2, \
					    'i');			\
	} else if (G_UNLIKELY (memcmp (__s1, __s2, __l1) != 0)) {	\
		g_assertion_message (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, \
				     "assertion failed (" #s1 " == " #s2 ")"); \
	}								\
} G_STMT_END
