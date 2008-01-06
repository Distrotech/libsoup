/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_MESSAGE_H
#define SOUP_MESSAGE_H 1

#include <libsoup/soup-types.h>
#include <libsoup/soup-message-body.h>
#include <libsoup/soup-message-headers.h>
#include <libsoup/soup-method.h>

G_BEGIN_DECLS

#define SOUP_TYPE_MESSAGE            (soup_message_get_type ())
#define SOUP_MESSAGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_MESSAGE, SoupMessage))
#define SOUP_MESSAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_MESSAGE, SoupMessageClass))
#define SOUP_IS_MESSAGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_MESSAGE))
#define SOUP_IS_MESSAGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_MESSAGE))
#define SOUP_MESSAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_MESSAGE, SoupMessageClass))

/**
 * SoupMessage:
 * @method: the HTTP method
 * @status_code: the HTTP status code
 * @reason_phrase: the status phrase associated with @status_code
 * @request_body: the request body
 * @request_headers: the request headers
 * @response_body: the response body
 * @response_headers: the response headers
 *
 * Represents an HTTP message being sent or received.
 *
 * As described in the #SoupMessageBody documentation, the
 * @request_body and @response_body %data fields will not necessarily
 * be filled in at all times. When they are filled in, they will be
 * terminated with a '\0' byte (which is not included in the %length),
 * so you can use them as ordinary C strings (assuming that you know
 * that the body doesn't have any other '\0' bytes).
 *
 * For a client-side #SoupMessage, @request_body's %data is usually
 * filled in right before libsoup writes the request to the network,
 * but you should not count on this; use soup_message_body_flatten()
 * if you want to ensure that %data is filled in. @response_body's
 * %data will be filled in before #SoupMessage::finished is emitted,
 * unless you set the %SOUP_MESSAGE_OVERWRITE_CHUNKS flag.
 *
 * For a server-side #SoupMessage, @request_body's %data will be
 * filled in before #SoupMessage::got_body is emitted.
 **/
struct SoupMessage {
	GObject parent;

	/*< public >*/
	const char         *method;

	guint               status_code;
	const char         *reason_phrase;

	SoupMessageBody    *request_body;
	SoupMessageHeaders *request_headers;

	SoupMessageBody    *response_body;
	SoupMessageHeaders *response_headers;
};

typedef struct {
	GObjectClass parent_class;

	/* signals */
	void     (*wrote_informational) (SoupMessage *msg);
	void     (*wrote_headers)       (SoupMessage *msg);
	void     (*wrote_chunk)         (SoupMessage *msg);
	void     (*wrote_body)          (SoupMessage *msg);
	void     (*got_informational)   (SoupMessage *msg);
	void     (*got_headers)         (SoupMessage *msg);
	void     (*got_chunk)           (SoupMessage *msg, SoupBuffer *chunk);
	void     (*got_body)            (SoupMessage *msg);
	void     (*restarted)           (SoupMessage *msg);
	void     (*finished)            (SoupMessage *msg);
} SoupMessageClass;

GType soup_message_get_type (void);

#define SOUP_MESSAGE_METHOD        "method"
#define SOUP_MESSAGE_URI           "uri"
#define SOUP_MESSAGE_HTTP_VERSION  "http-version"
#define SOUP_MESSAGE_FLAGS         "flags"
#define SOUP_MESSAGE_STATUS_CODE   "status-code"
#define SOUP_MESSAGE_REASON_PHRASE "reason-phrase"

SoupMessage   *soup_message_new                 (const char        *method,
						 const char        *uri_string);
SoupMessage   *soup_message_new_from_uri        (const char        *method,
						 SoupURI           *uri);

void           soup_message_set_request         (SoupMessage       *msg,
						 const char        *content_type,
						 SoupMemoryUse      req_use,
						 const char        *req_body,
						 gsize              req_length);
void           soup_message_set_response        (SoupMessage       *msg,
						 const char        *content_type,
						 SoupMemoryUse      resp_use,
						 const char        *resp_body,
						 gsize              resp_length);

/**
 * SoupHTTPVersion:
 * @SOUP_HTTP_1_0: HTTP 1.0 (RFC 1945)
 * @SOUP_HTTP_1_1: HTTP 1.1 (RFC 2616)
 *
 * Indicates the HTTP protocol version being used.
 **/
typedef enum {
	SOUP_HTTP_1_0 = 0,
	SOUP_HTTP_1_1 = 1
} SoupHTTPVersion;

void             soup_message_set_http_version    (SoupMessage       *msg,
						   SoupHTTPVersion    version);
SoupHTTPVersion  soup_message_get_http_version    (SoupMessage       *msg);

gboolean         soup_message_is_keepalive        (SoupMessage       *msg);

SoupURI         *soup_message_get_uri             (SoupMessage       *msg);
void             soup_message_set_uri             (SoupMessage       *msg,
						   SoupURI           *uri);

/**
 * SoupMessageFlags:
 * @SOUP_MESSAGE_NO_REDIRECT: The session should not follow redirect
 * (3xx) responses received by this message.
 * @SOUP_MESSAGE_OVERWRITE_CHUNKS: Each chunk of the response will be
 * freed after its corresponding %got_chunk signal is emitted, meaning
 * %response will still be empty after the message is complete. You
 * can use this to save memory if you expect the response to be large
 * and you are able to process it a chunk at a time.
 *
 * Various flags that can be set on a #SoupMessage to alter its
 * behavior.
 **/
typedef enum {
	SOUP_MESSAGE_NO_REDIRECT      = (1 << 1),
	SOUP_MESSAGE_OVERWRITE_CHUNKS = (1 << 3),
} SoupMessageFlags;

void           soup_message_set_flags           (SoupMessage        *msg,
						 guint               flags);

guint          soup_message_get_flags           (SoupMessage        *msg);

/* Specialized signal handlers */
guint          soup_message_add_header_handler  (SoupMessage       *msg,
						 const char        *signal,
						 const char        *header,
						 GCallback          callback,
						 gpointer           user_data);

guint          soup_message_add_status_code_handler (
						 SoupMessage       *msg,
						 const char        *signal,
						 guint              status_code,
						 GCallback          callback,
						 gpointer           user_data);

/*
 * Status Setting
 */
void           soup_message_set_status          (SoupMessage       *msg, 
						 guint              status_code);

void           soup_message_set_status_full     (SoupMessage       *msg, 
						 guint              status_code, 
						 const char        *reason_phrase);


void soup_message_wrote_informational (SoupMessage *msg);
void soup_message_wrote_headers       (SoupMessage *msg);
void soup_message_wrote_chunk         (SoupMessage *msg);
void soup_message_wrote_body          (SoupMessage *msg);
void soup_message_got_informational   (SoupMessage *msg);
void soup_message_got_headers         (SoupMessage *msg);
void soup_message_got_chunk           (SoupMessage *msg, SoupBuffer *chunk);
void soup_message_got_body            (SoupMessage *msg);
void soup_message_restarted           (SoupMessage *msg);
void soup_message_finished            (SoupMessage *msg);

G_END_DECLS

#endif /*SOUP_MESSAGE_H*/
