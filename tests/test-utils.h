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

extern int debug_level, errors;
extern gboolean parallelize;
extern gboolean expect_warning, tls_available;
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

typedef enum {
  SOUP_TEST_SERVER_DEFAULT   = 0,
  SOUP_TEST_SERVER_IN_THREAD = (1 << 0)
} SoupTestServerOptions;

SoupServer  *soup_test_server_new            (SoupTestServerOptions  options);
SoupURI     *soup_test_server_get_uri        (SoupServer            *server,
					      const char            *scheme,
					      const char            *host);
void         soup_test_server_quit_unref     (SoupServer            *server);

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
