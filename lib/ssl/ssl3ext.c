/*
 * SSL3 Protocol
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* TLS extension code moved here from ssl3ecc.c */

#include "nssrenam.h"
#include "nss.h"
#include "ssl.h"
#include "sslproto.h"
#include "sslimpl.h"
#include "pk11pub.h"
#ifdef NO_PKCS11_BYPASS
#include "blapit.h"
#else
#include "blapi.h"
#endif
#include "prinit.h"

static unsigned char  key_name[SESS_TICKET_KEY_NAME_LEN];
static PK11SymKey    *session_ticket_enc_key_pkcs11 = NULL;
static PK11SymKey    *session_ticket_mac_key_pkcs11 = NULL;

#ifndef NO_PKCS11_BYPASS
static unsigned char  session_ticket_enc_key[AES_256_KEY_LENGTH];
static unsigned char  session_ticket_mac_key[SHA256_LENGTH];

static PRBool         session_ticket_keys_initialized = PR_FALSE;
#endif
static PRCallOnceType generate_session_keys_once;

/* forward static function declarations */
static SECStatus ssl3_ParseEncryptedSessionTicket(sslSocket *ss,
    SECItem *data, EncryptedSessionTicket *enc_session_ticket);
static SECStatus ssl3_AppendToItem(SECItem *item, const unsigned char *buf,
    PRUint32 bytes);
static SECStatus ssl3_AppendNumberToItem(SECItem *item, PRUint32 num,
    PRInt32 lenSize);
static SECStatus ssl3_GetSessionTicketKeysPKCS11(sslSocket *ss,
    PK11SymKey **aes_key, PK11SymKey **mac_key);
#ifndef NO_PKCS11_BYPASS
static SECStatus ssl3_GetSessionTicketKeys(const unsigned char **aes_key,
    PRUint32 *aes_key_length, const unsigned char **mac_key,
    PRUint32 *mac_key_length);
#endif
static PRInt32 ssl3_SendRenegotiationInfoXtn(void *context, SSL_Socket *fd,
                                             PRBool append, PRUint32 maxBytes);
static SECStatus ssl3_HandleRenegotiationInfoXtn(sslSocket *ss, 
    PRUint16 ex_type, SECItem *data);
static SECStatus ssl3_ClientHandleNextProtoNegoXtn(sslSocket *ss,
			PRUint16 ex_type, SECItem *data);
static SECStatus ssl3_ServerHandleNextProtoNegoXtn(sslSocket *ss,
			PRUint16 ex_type, SECItem *data);
static PRInt32 ssl3_ClientSendNextProtoNegoXtn(void *context, SSL_Socket *fd,
                                               PRBool append, PRUint32 maxBytes);
static PRInt32 ssl3_SendUseSRTPXtn(void *context, SSL_Socket *fd,
                                   PRBool append, PRUint32 maxBytes);
static SECStatus ssl3_HandleUseSRTPXtn(sslSocket * ss, PRUint16 ex_type,
    SECItem *data);
static SECStatus ssl3_ServerSendStatusRequestXtn(void *context, SSL_Socket *fd,
                                                 PRBool append, PRUint32 maxBytes);
static SECStatus ssl3_ClientHandleStatusRequestXtn(sslSocket *ss,
                                                   PRUint16 ex_type,
                                                   SECItem *data);
static PRInt32 ssl3_ClientSendStatusRequestXtn(void *context, SSL_Socket *fd, PRBool append,
                                               PRUint32 maxBytes);
static PRInt32 ssl3_ClientSendSigAlgsXtn(void *context, SSL_Socket *fd, PRBool append,
                                         PRUint32 maxBytes);
static SECStatus ssl3_ServerHandleSigAlgsXtn(sslSocket *ss, PRUint16 ex_type,
                                             SECItem *data);
static SECStatus ssl3_ServerHandleStatusRequestXtn(sslSocket *ss, PRUint16 ex_type,
                                                   SECItem *data);

/*
 * Write bytes.  Using this function means the SECItem structure
 * cannot be freed.  The caller is expected to call this function
 * on a shallow copy of the structure.
 */
static SECStatus
ssl3_AppendToItem(SECItem *item, const unsigned char *buf, PRUint32 bytes)
{
    if (bytes > item->len)
	return SECFailure;

    PORT_Memcpy(item->data, buf, bytes);
    item->data += bytes;
    item->len -= bytes;
    return SECSuccess;
}

/*
 * Write a number in network byte order. Using this function means the
 * SECItem structure cannot be freed.  The caller is expected to call
 * this function on a shallow copy of the structure.
 */
static SECStatus
ssl3_AppendNumberToItem(SECItem *item, PRUint32 num, PRInt32 lenSize)
{
    SECStatus rv;
    PRUint8   b[4];
    PRUint8 * p = b;

    switch (lenSize) {
    case 4:
	*p++ = (PRUint8) (num >> 24);
    case 3:
	*p++ = (PRUint8) (num >> 16);
    case 2:
	*p++ = (PRUint8) (num >> 8);
    case 1:
	*p = (PRUint8) num;
    }
    rv = ssl3_AppendToItem(item, &b[0], lenSize);
    return rv;
}

static SECStatus ssl3_SessionTicketShutdown(void* appData, void* nssData)
{
    if (session_ticket_enc_key_pkcs11) {
	PK11_FreeSymKey(session_ticket_enc_key_pkcs11);
	session_ticket_enc_key_pkcs11 = NULL;
    }
    if (session_ticket_mac_key_pkcs11) {
	PK11_FreeSymKey(session_ticket_mac_key_pkcs11);
	session_ticket_mac_key_pkcs11 = NULL;
    }
    PORT_Memset(&generate_session_keys_once, 0,
	sizeof(generate_session_keys_once));
    return SECSuccess;
}


static PRStatus
ssl3_GenerateSessionTicketKeysPKCS11(void *data)
{
    SECStatus rv;
    sslSocket *ss = (sslSocket *)data;
    SECKEYPrivateKey *svrPrivKey = ss->serverCerts[kt_rsa].SERVERKEY;
    SECKEYPublicKey *svrPubKey = ss->serverCerts[kt_rsa].serverKeyPair->pubKey;

    if (svrPrivKey == NULL || svrPubKey == NULL) {
	SSL_DBG(("%d: SSL[%d]: Pub or priv key(s) is NULL.",
			SSL_GETPID(), ss->fd));
	goto loser;
    }

    /* Get a copy of the session keys from shared memory. */
    PORT_Memcpy(key_name, SESS_TICKET_KEY_NAME_PREFIX,
	sizeof(SESS_TICKET_KEY_NAME_PREFIX));
    if (!ssl_GetSessionTicketKeysPKCS11(svrPrivKey, svrPubKey,
	    ss->pkcs11PinArg, &key_name[SESS_TICKET_KEY_NAME_PREFIX_LEN],
	    &session_ticket_enc_key_pkcs11, &session_ticket_mac_key_pkcs11))
	return PR_FAILURE;

    rv = NSS_RegisterShutdown(ssl3_SessionTicketShutdown, NULL);
    if (rv != SECSuccess)
	goto loser;

    return PR_SUCCESS;

loser:
    ssl3_SessionTicketShutdown(NULL, NULL);
    return PR_FAILURE;
}

static SECStatus
ssl3_GetSessionTicketKeysPKCS11(sslSocket *ss, PK11SymKey **aes_key,
                                PK11SymKey **mac_key)
{
    if (PR_CallOnceWithArg(&generate_session_keys_once,
	    ssl3_GenerateSessionTicketKeysPKCS11, ss) != PR_SUCCESS)
	return SECFailure;

    if (session_ticket_enc_key_pkcs11 == NULL ||
	session_ticket_mac_key_pkcs11 == NULL)
	return SECFailure;

    *aes_key = session_ticket_enc_key_pkcs11;
    *mac_key = session_ticket_mac_key_pkcs11;
    return SECSuccess;
}

#ifndef NO_PKCS11_BYPASS
static PRStatus
ssl3_GenerateSessionTicketKeys(void)
{
    PORT_Memcpy(key_name, SESS_TICKET_KEY_NAME_PREFIX,
	sizeof(SESS_TICKET_KEY_NAME_PREFIX));

    if (!ssl_GetSessionTicketKeys(&key_name[SESS_TICKET_KEY_NAME_PREFIX_LEN],
	    session_ticket_enc_key, session_ticket_mac_key))
	return PR_FAILURE;

    session_ticket_keys_initialized = PR_TRUE;
    return PR_SUCCESS;
}

static SECStatus
ssl3_GetSessionTicketKeys(const unsigned char **aes_key,
    PRUint32 *aes_key_length, const unsigned char **mac_key,
    PRUint32 *mac_key_length)
{
    if (PR_CallOnce(&generate_session_keys_once,
	    ssl3_GenerateSessionTicketKeys) != PR_SUCCESS)
	return SECFailure;

    if (!session_ticket_keys_initialized)
	return SECFailure;

    *aes_key = session_ticket_enc_key;
    *aes_key_length = sizeof(session_ticket_enc_key);
    *mac_key = session_ticket_mac_key;
    *mac_key_length = sizeof(session_ticket_mac_key);

    return SECSuccess;
}
#endif


void
uint16ArrayInit(Uint16Array *arr) {
    arr->alloc_len = 4;
    arr->data = PORT_Alloc(arr->alloc_len * sizeof(*arr));
    arr->len = 0;
}

void
uint16ArrayAppend(Uint16Array *arr, PRUint16 new_data) {
    if (arr->alloc_len == arr->len) {
        arr->alloc_len *= 2;
        arr->data = PORT_Realloc(arr->data, arr->alloc_len * sizeof(*arr));
    }

    arr->data[arr->len] = new_data;
    ++arr->len;
}


/* Table of handlers for received TLS hello extensions, one per extension.
 * In the second generation, this table will be dynamic, and functions
 * will be registered here.
 */
/* This table is used by the server, to handle client hello extensions. */
static const ssl3HelloExtensionHandler builtinClientHelloHandlers[] = {
    { ssl_server_name_xtn,        &ssl3_HandleServerNameXtn },
#ifdef NSS_ENABLE_ECC
    { ssl_elliptic_curves_xtn,    &ssl3_HandleSupportedCurvesXtn },
    { ssl_ec_point_formats_xtn,   &ssl3_HandleSupportedPointFormatsXtn },
#endif
    { ssl_session_ticket_xtn,     &ssl3_ServerHandleSessionTicketXtn },
    { ssl_renegotiation_info_xtn, &ssl3_HandleRenegotiationInfoXtn },
    { ssl_next_proto_nego_xtn,    &ssl3_ServerHandleNextProtoNegoXtn },
    { ssl_use_srtp_xtn,           &ssl3_HandleUseSRTPXtn },
    { ssl_cert_status_xtn,        &ssl3_ServerHandleStatusRequestXtn },
    { ssl_signature_algorithms_xtn, &ssl3_ServerHandleSigAlgsXtn },
};
static ssl3HelloExtensionHandlerCollection clientHelloHandlers = {
    builtinClientHelloHandlers, -1/* needs to be computed */, NULL, 0, 0
};


/* These two tables are used by the client, to handle server hello
 * extensions. */
static const ssl3HelloExtensionHandler builtinServerHelloHandlersTLS[] = {
    { ssl_server_name_xtn,        &ssl3_HandleServerNameXtn },
    /* TODO: add a handler for ssl_ec_point_formats_xtn */
    { ssl_session_ticket_xtn,     &ssl3_ClientHandleSessionTicketXtn },
    { ssl_renegotiation_info_xtn, &ssl3_HandleRenegotiationInfoXtn },
    { ssl_next_proto_nego_xtn,    &ssl3_ClientHandleNextProtoNegoXtn },
    { ssl_use_srtp_xtn,           &ssl3_HandleUseSRTPXtn },
    { ssl_cert_status_xtn,        &ssl3_ClientHandleStatusRequestXtn },
};
static ssl3HelloExtensionHandlerCollection serverHelloHandlersTLS = {
    builtinServerHelloHandlersTLS, -1, NULL, 0, 0
};

static const ssl3HelloExtensionHandler builtinServerHelloHandlersSSL3[] = {
    { ssl_renegotiation_info_xtn, &ssl3_HandleRenegotiationInfoXtn },
};
static ssl3HelloExtensionHandlerCollection serverHelloHandlersSSL3 = {
    builtinServerHelloHandlersSSL3, -1, NULL, 0, 0
};


/* Tables of functions to format TLS hello extensions, one function per
 * extension.
 * These static tables are for the formatting of client hello extensions.
 * The server's table of hello senders is dynamic, in the socket struct,
 * and sender functions are registered there.
 */
static const 
ssl3HelloExtensionSender builtinClientHelloSendersTLS[] = {
    { ssl_server_name_xtn,        &ssl3_SendServerNameXtn,            NULL },
    { ssl_renegotiation_info_xtn, &ssl3_SendRenegotiationInfoXtn,     NULL },
#ifdef NSS_ENABLE_ECC
    { ssl_elliptic_curves_xtn,    &ssl3_SendSupportedCurvesXtn,       NULL },
    { ssl_ec_point_formats_xtn,   &ssl3_SendSupportedPointFormatsXtn, NULL },
#endif
    { ssl_session_ticket_xtn,     &ssl3_SendSessionTicketXtn,         NULL },
    { ssl_next_proto_nego_xtn,    &ssl3_ClientSendNextProtoNegoXtn,   NULL },
    { ssl_use_srtp_xtn,           &ssl3_SendUseSRTPXtn,               NULL },
    { ssl_cert_status_xtn,        &ssl3_ClientSendStatusRequestXtn,   NULL },
    { ssl_signature_algorithms_xtn, &ssl3_ClientSendSigAlgsXtn,       NULL }
};
static
ssl3HelloSenderCollection clientHelloSendersTLS = { NULL, -1, -1 };


static const 
ssl3HelloExtensionSender builtinClientHelloSendersSSL3[] = {
    { ssl_renegotiation_info_xtn, &ssl3_SendRenegotiationInfoXtn, NULL }
};
static
ssl3HelloSenderCollection clientHelloSendersSSL3 = { NULL, -1, -1 };

/* Initialize coll, whose builtin must already be populated. */
static void
hello_extension_collection_init(ssl3HelloExtensionHandlerCollection *coll) {
    int i;
    for (i = 0; coll->builtin_handlers[i].ex_type > 0; i++) {
        // Counting how many there are
    }
    coll->builtin_len = i + 1;
}

/* Returns PR_TRUE if coll has had _init called, else PR_FALSE */
static PRBool
hello_extension_collection_is_inited(ssl3HelloExtensionHandlerCollection *coll) {
    return coll->builtin_len == -1;
}

/* Init if not already inited */
static void
hello_extension_collection_ensure_inited(ssl3HelloExtensionHandlerCollection *coll) {
    if (hello_extension_collection_is_inited(coll)) {
        hello_extension_collection_init(coll);
    }
}

/* Append handler to coll->custom_handlers. */
static void
hello_extension_collection_append(ssl3HelloExtensionHandlerCollection *coll,
                                  ssl3CustomHelloExtensionHandler *handler) {
    // Make sure we have space to append.
    if (coll->custom_len == 0) {
        // custom_handlers is NULL. allocate it
        coll->custom_alloced_len = INITIAL_CUSTOM_HANDLERS_ARR_SIZE;
        coll->custom_handlers = PORT_Alloc(sizeof(*coll->custom_handlers) * coll->custom_alloced_len);
    } else if (coll->custom_len == coll->custom_alloced_len) {
        // Array is full.
        coll->custom_len *= 2;
        coll->custom_handlers = PORT_Realloc(coll->custom_handlers,
                                             sizeof(*coll->custom_handlers) * coll->custom_len);
    }
    // Append
    coll->custom_handlers[coll->custom_len] = *handler;
    ++coll->custom_len;
}

/* Frees memory allocated on behalf of coll, but does not free coll itself */
static void
hello_extension_collection_destroy(ssl3HelloExtensionHandlerCollection *coll) {
    if (coll->custom_handlers != NULL) {
        free(coll->custom_handlers);
    }
}

/* Iterator over all handlers in coll */
typedef struct {
    ssl3HelloExtensionHandlerCollection *coll;
    PRBool on_builtin;
    PRInt32 next_idx;
} ssl3HelloExtensionHandlerCollectionIterator;

/* Abstract interface to either an ssl3HelloExtensionHandler or an
   ssl3CustomHelloExtensionHandler.
    Returned by the Iterator. */
typedef struct {
    PRBool is_builtin;
    union {
        const ssl3HelloExtensionHandler *builtin;
        ssl3CustomHelloExtensionHandler *client_supplied;
    };
} ssl3AbstractHelloExtensionHandler;


/* Initialize iter to be an iterator over coll.
   Also ensure that coll has been initialized. */
static void
hello_extension_collection_iterator(ssl3HelloExtensionHandlerCollectionIterator *iter,
                                    ssl3HelloExtensionHandlerCollection *coll) {
    iter->coll = coll;
    hello_extension_collection_ensure_inited(iter->coll);
    // Start with the builtin ones, if there are any.
    iter->on_builtin = coll->builtin_len > 0;
    iter->next_idx = 0;
}

/* Returns PR_TRUE if iter has more handlers to return, else PR_FALSE */
static PRBool
hello_extension_collection_iterator_has_next(ssl3HelloExtensionHandlerCollectionIterator *iter) {
    if (iter->on_builtin) {
        // onBuiltin will only be true if there are builtin handlers and we
        // haven't returned the last one.
        return PR_TRUE;
    } else {
        return iter->next_idx < iter->coll->custom_len;
    }
}

/* Populate handler with the next handler in iter.*/
static void
hello_extension_collection_iterator_pop(ssl3AbstractHelloExtensionHandler *handler,
                                        ssl3HelloExtensionHandlerCollectionIterator *iter) {
    PORT_Assert(hello_extension_collection_iterator_has_next(iter));
    if (iter->on_builtin) {
        handler->builtin = &iter->coll->builtin_handlers[iter->next_idx++];
        handler->is_builtin = PR_TRUE;

        // Check if we've finished the builtin ones.
        if (iter->next_idx == iter->coll->builtin_len) {
            iter->on_builtin = PR_FALSE;
            iter->next_idx = 0;
        }
    } else {
        handler->is_builtin = PR_FALSE;
        handler->client_supplied = &iter->coll->custom_handlers[iter->next_idx++];
    }
}

/* Returns true if builtin should be used, false if client_supplied should be used. */
static PRBool
abstract_extension_handler_is_builtin(ssl3AbstractHelloExtensionHandler *abstract_handler) {
    return abstract_handler->is_builtin;
}

/* Returns the extension type number of handler */
static PRInt32
abstract_extension_handler_ex_type(ssl3AbstractHelloExtensionHandler *handler){
    if (abstract_extension_handler_is_builtin(handler)) {
        return handler->builtin->ex_type;
    } else {
        return handler->client_supplied->ex_type;
    }
}

/* Call the handler callback stored by handler. */
static SECStatus
abstract_extension_handler_call(ssl3AbstractHelloExtensionHandler *handler,
                                sslSocket *ss, PRUint16 ex_type, SECItem *data) {
    if (abstract_extension_handler_is_builtin(handler)) {
        return handler->builtin->ex_handler(ss, ex_type, data);
    } else {
        return handler->client_supplied->ex_handler(handler->client_supplied->context,
                                                     ss->fd, ex_type, data);
    }
}

/* Initialize coll, starting its senders with builtin, which is a
   total of builtin_bytes bytes long. */
static void
ssl3_ExtensionSenderCollectionInit(ssl3HelloSenderCollection *coll,
                         const ssl3HelloExtensionSender *builtin,
                         PRInt32 builtin_bytes) {
    coll->alloc_len = coll->len = builtin_bytes / sizeof(*builtin);
    if (builtin_bytes > 0) {
        coll->senders = PORT_Alloc(builtin_bytes);
    } else {
        // We won't use the space for now, but we still want
        // a non-null return value so we know it is inited.
        // TODO Hacky. Add an inited flag instead?
        coll->senders = PORT_Alloc(1);
    }
    PORT_Memcpy(coll->senders, builtin, builtin_bytes);
}

/* Call Init on coll iff it has not been inited. */
static void
ssl3_ExtensionSenderCollectionEnsureInited(ssl3HelloSenderCollection *coll,
                                           const ssl3HelloExtensionSender *builtin,
                                           PRInt32 builtin_bytes) {
    if (coll->senders == NULL) {
        ssl3_ExtensionSenderCollectionInit(coll, builtin, builtin_bytes);
    }
}

/* Append sender to coll's list of senders. */
static void
ssl3_ExtensionSenderCollectionAppend(ssl3HelloSenderCollection *coll,
                                     ssl3HelloExtensionSender* sender) {
    PORT_Assert(coll->senders != NULL);
    if (coll->len == coll->alloc_len) {
        coll->alloc_len *= 2; // TODO if starts with 0 builtin, will fail.
        coll->senders = PORT_Realloc(coll->senders,
                                     sizeof(*coll->senders) * coll->alloc_len);
    }

    coll->senders[coll->len] = *sender;
    ++coll->len;
}

static PRBool
arrayContainsExtension(const PRUint16 *array, PRUint32 len, PRUint16 ex_type)
{
    int i;
    for (i = 0; i < len; i++) {
	if (ex_type == array[i])
	    return PR_TRUE;
    }
    return PR_FALSE;
}

PRBool
ssl3_ExtensionNegotiated(sslSocket *ss, PRUint16 ex_type) {
    TLSExtensionData *xtnData = &ss->xtnData;
    return arrayContainsExtension(xtnData->negotiated.data,
	                          xtnData->negotiated.len, ex_type);
}

static PRBool
ssl3_ClientExtensionAdvertised(sslSocket *ss, PRUint16 ex_type) {
    TLSExtensionData *xtnData = &ss->xtnData;
    return arrayContainsExtension(xtnData->advertised.data,
	                          xtnData->advertised.len, ex_type);
}

/* Format an SNI extension, using the name from the socket's URL,
 * unless that name is a dotted decimal string.
 * Used by client and server.
 */
PRInt32
ssl3_SendServerNameXtn(void *context, SSL_Socket *fd, PRBool append,
                       PRUint32 maxBytes)
{
    sslSocket *ss = ssl_UnpackSocket(fd);
    PORT_Assert(ss != NULL);

    SECStatus rv;
    if (!ss)
    	return 0;
    if (!ss->sec.isServer) {
        PRUint32 len;
        PRNetAddr netAddr;
        
        /* must have a hostname */
        if (!ss->url || !ss->url[0])
            return 0;
        /* must not be an IPv4 or IPv6 address */
        if (PR_SUCCESS == PR_StringToNetAddr(ss->url, &netAddr)) {
            /* is an IP address (v4 or v6) */
            return 0;
        }
        len  = PORT_Strlen(ss->url);
        if (append && maxBytes >= len + 9) {
            /* extension_type */
            rv = ssl3_AppendHandshakeNumber(ss, ssl_server_name_xtn, 2); 
            if (rv != SECSuccess) return -1;
            /* length of extension_data */
            rv = ssl3_AppendHandshakeNumber(ss, len + 5, 2); 
            if (rv != SECSuccess) return -1;
            /* length of server_name_list */
            rv = ssl3_AppendHandshakeNumber(ss, len + 3, 2);
            if (rv != SECSuccess) return -1;
            /* Name Type (sni_host_name) */
            rv = ssl3_AppendHandshake(ss,       "\0",    1);
            if (rv != SECSuccess) return -1;
            /* HostName (length and value) */
            rv = ssl3_AppendHandshakeVariable(ss, (PRUint8 *)ss->url, len, 2);
            if (rv != SECSuccess) return -1;
            if (!ss->sec.isServer) {
                TLSExtensionData *xtnData = &ss->xtnData;
                uint16ArrayAppend(&xtnData->advertised, ssl_server_name_xtn);
            }
        }
        return len + 9;
    }
    /* Server side */
    if (append && maxBytes >= 4) {
        rv = ssl3_AppendHandshakeNumber(ss, ssl_server_name_xtn, 2);
        if (rv != SECSuccess)  return -1;
        /* length of extension_data */
        rv = ssl3_AppendHandshakeNumber(ss, 0, 2);
        if (rv != SECSuccess) return -1;
    }
    return 4;
}

/* handle an incoming SNI extension, by ignoring it. */
SECStatus
ssl3_HandleServerNameXtn(sslSocket * ss, PRUint16 ex_type, SECItem *data)
{
    SECItem *names = NULL;
    PRUint32 listCount = 0, namesPos = 0, i;
    TLSExtensionData *xtnData = &ss->xtnData;
    SECItem  ldata;
    PRInt32  listLenBytes = 0;

    if (!ss->sec.isServer) {
        /* Verify extension_data is empty. */
        if (data->data || data->len ||
            !ssl3_ExtensionNegotiated(ss, ssl_server_name_xtn)) {
            /* malformed or was not initiated by the client.*/
            return SECFailure;
        }
        return SECSuccess;
    }

    /* Server side - consume client data and register server sender. */
    /* do not parse the data if don't have user extension handling function. */
    if (!ss->sniSocketConfig) {
        return SECSuccess;
    }
    /* length of server_name_list */
    listLenBytes = ssl3_ConsumeHandshakeNumber(ss, 2, &data->data, &data->len); 
    if (listLenBytes == 0 || listLenBytes != data->len) {
        return SECFailure;
    }
    ldata = *data;
    /* Calculate the size of the array.*/
    while (listLenBytes > 0) {
        SECItem litem;
        SECStatus rv;
        PRInt32  type;
        /* Name Type (sni_host_name) */
        type = ssl3_ConsumeHandshakeNumber(ss, 1, &ldata.data, &ldata.len); 
        if (!ldata.len) {
            return SECFailure;
        }
        rv = ssl3_ConsumeHandshakeVariable(ss, &litem, 2, &ldata.data, &ldata.len);
        if (rv != SECSuccess) {
            return SECFailure;
        }
        /* Adjust total length for cunsumed item, item len and type.*/
        listLenBytes -= litem.len + 3;
        if (listLenBytes > 0 && !ldata.len) {
            return SECFailure;
        }
        listCount += 1;
    }
    if (!listCount) {
        return SECFailure;
    }
    names = PORT_ZNewArray(SECItem, listCount);
    if (!names) {
        return SECFailure;
    }
    for (i = 0;i < listCount;i++) {
        int j;
        PRInt32  type;
        SECStatus rv;
        PRBool nametypePresent = PR_FALSE;
        /* Name Type (sni_host_name) */
        type = ssl3_ConsumeHandshakeNumber(ss, 1, &data->data, &data->len); 
        /* Check if we have such type in the list */
        for (j = 0;j < listCount && names[j].data;j++) {
            if (names[j].type == type) {
                nametypePresent = PR_TRUE;
                break;
            }
        }
        /* HostName (length and value) */
        rv = ssl3_ConsumeHandshakeVariable(ss, &names[namesPos], 2,
                                           &data->data, &data->len);
        if (rv != SECSuccess) {
            goto loser;
        }
        if (nametypePresent == PR_FALSE) {
            namesPos += 1;
        }
    }
    /* Free old and set the new data. */
    if (xtnData->sniNameArr) {
        PORT_Free(ss->xtnData.sniNameArr);
    }
    xtnData->sniNameArr = names;
    xtnData->sniNameArrSize = namesPos;
    uint16ArrayAppend(&xtnData->negotiated, ssl_server_name_xtn);

    return SECSuccess;

loser:
    PORT_Free(names);
    return SECFailure;
}
        
/* Called by both clients and servers.
 * Clients sends a filled in session ticket if one is available, and otherwise
 * sends an empty ticket.  Servers always send empty tickets.
 */
PRInt32
ssl3_SendSessionTicketXtn(void *context, SSL_Socket *fd, PRBool append,
                          PRUint32 maxBytes)
{
    sslSocket *ss = ssl_UnpackSocket(fd);
    PORT_Assert(ss != NULL);

    PRInt32 extension_length;
    NewSessionTicket *session_ticket = NULL;

    /* Ignore the SessionTicket extension if processing is disabled. */
    if (!ss->opt.enableSessionTickets)
	return 0;

    /* Empty extension length = extension_type (2-bytes) +
     * length(extension_data) (2-bytes)
     */
    extension_length = 4;

    /* If we are a client then send a session ticket if one is availble.
     * Servers that support the extension and are willing to negotiate the
     * the extension always respond with an empty extension.
     */
    if (!ss->sec.isServer) {
	sslSessionID *sid = ss->sec.ci.sid;
	session_ticket = &sid->u.ssl3.sessionTicket;
	if (session_ticket->ticket.data) {
	    if (ss->xtnData.ticketTimestampVerified) {
		extension_length += session_ticket->ticket.len;
	    } else if (!append &&
		(session_ticket->ticket_lifetime_hint == 0 ||
		(session_ticket->ticket_lifetime_hint +
		    session_ticket->received_timestamp > ssl_Time()))) {
		extension_length += session_ticket->ticket.len;
		ss->xtnData.ticketTimestampVerified = PR_TRUE;
	    }
	}
    }

    if (append && maxBytes >= extension_length) {
	SECStatus rv;
	/* extension_type */
        rv = ssl3_AppendHandshakeNumber(ss, ssl_session_ticket_xtn, 2);
        if (rv != SECSuccess)
	    goto loser;
	if (session_ticket && session_ticket->ticket.data &&
	    ss->xtnData.ticketTimestampVerified) {
	    rv = ssl3_AppendHandshakeVariable(ss, session_ticket->ticket.data,
		session_ticket->ticket.len, 2);
	    ss->xtnData.ticketTimestampVerified = PR_FALSE;
	} else {
	    rv = ssl3_AppendHandshakeNumber(ss, 0, 2);
	}
        if (rv != SECSuccess)
	    goto loser;

	if (!ss->sec.isServer) {
	    TLSExtensionData *xtnData = &ss->xtnData;
	    uint16ArrayAppend(&xtnData->advertised, ssl_session_ticket_xtn);
	}
    } else if (maxBytes < extension_length) {
	PORT_Assert(0);
        return 0;
    }
    return extension_length;

 loser:
    ss->xtnData.ticketTimestampVerified = PR_FALSE;
    return -1;
}

/* handle an incoming Next Protocol Negotiation extension. */
static SECStatus
ssl3_ServerHandleNextProtoNegoXtn(sslSocket * ss, PRUint16 ex_type, SECItem *data)
{
    if (ss->firstHsDone || data->len != 0) {
	/* Clients MUST send an empty NPN extension, if any. */
	PORT_SetError(SSL_ERROR_NEXT_PROTOCOL_DATA_INVALID);
	return SECFailure;
    }

    uint16ArrayAppend(&ss->xtnData.negotiated, ex_type);

    /* TODO: server side NPN support would require calling
     * ssl3_RegisterServerHelloExtensionSender here in order to echo the
     * extension back to the client. */

    return SECSuccess;
}

/* ssl3_ValidateNextProtoNego checks that the given block of data is valid: none
 * of the lengths may be 0 and the sum of the lengths must equal the length of
 * the block. */
SECStatus
ssl3_ValidateNextProtoNego(const unsigned char* data, unsigned int length)
{
    unsigned int offset = 0;

    while (offset < length) {
	unsigned int newOffset = offset + 1 + (unsigned int) data[offset];
	/* Reject embedded nulls to protect against buggy applications that
	 * store protocol identifiers in null-terminated strings.
	 */
	if (newOffset > length || data[offset] == 0) {
	    PORT_SetError(SSL_ERROR_NEXT_PROTOCOL_DATA_INVALID);
	    return SECFailure;
	}
	offset = newOffset;
    }

    if (offset > length) {
	PORT_SetError(SSL_ERROR_NEXT_PROTOCOL_DATA_INVALID);
	return SECFailure;
    }

    return SECSuccess;
}

static SECStatus
ssl3_ClientHandleNextProtoNegoXtn(sslSocket *ss, PRUint16 ex_type,
				  SECItem *data)
{
    SECStatus rv;
    unsigned char resultBuffer[255];
    SECItem result = { siBuffer, resultBuffer, 0 };

    PORT_Assert(!ss->firstHsDone);

    rv = ssl3_ValidateNextProtoNego(data->data, data->len);
    if (rv != SECSuccess)
	return rv;

    /* ss->nextProtoCallback cannot normally be NULL if we negotiated the
     * extension. However, It is possible that an application erroneously
     * cleared the callback between the time we sent the ClientHello and now.
     */
    PORT_Assert(ss->nextProtoCallback != NULL);
    if (!ss->nextProtoCallback) {
	/* XXX Use a better error code. This is an application error, not an
	 * NSS bug. */
	PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
	return SECFailure;
    }

    rv = ss->nextProtoCallback(ss->nextProtoArg, ss->fd, data->data, data->len,
			       result.data, &result.len, sizeof resultBuffer);
    if (rv != SECSuccess)
	return rv;
    /* If the callback wrote more than allowed to |result| it has corrupted our
     * stack. */
    if (result.len > sizeof resultBuffer) {
	PORT_SetError(SEC_ERROR_OUTPUT_LEN);
	return SECFailure;
    }

    uint16ArrayAppend(&ss->xtnData.negotiated, ex_type);

    SECITEM_FreeItem(&ss->ssl3.nextProto, PR_FALSE);
    return SECITEM_CopyItem(NULL, &ss->ssl3.nextProto, &result);
}

static PRInt32
ssl3_ClientSendNextProtoNegoXtn(void *context, SSL_Socket *fd, PRBool append,
                                PRUint32 maxBytes)
{
    sslSocket *ss = ssl_UnpackSocket(fd);
    PORT_Assert(ss != NULL);

    PRInt32 extension_length;

    /* Renegotiations do not send this extension. */
    if (!ss->nextProtoCallback || ss->firstHsDone) {
	return 0;
    }

    extension_length = 4;

    if (append && maxBytes >= extension_length) {
	SECStatus rv;
	rv = ssl3_AppendHandshakeNumber(ss, ssl_next_proto_nego_xtn, 2);
	if (rv != SECSuccess)
	    goto loser;
	rv = ssl3_AppendHandshakeNumber(ss, 0, 2);
	if (rv != SECSuccess)
	    goto loser;
	uint16ArrayAppend(&ss->xtnData.advertised, ssl_next_proto_nego_xtn);
    } else if (maxBytes < extension_length) {
	return 0;
    }

    return extension_length;

loser:
    return -1;
}

static SECStatus
ssl3_ClientHandleStatusRequestXtn(sslSocket *ss, PRUint16 ex_type,
                                 SECItem *data)
{
    /* The echoed extension must be empty. */
    if (data->len != 0)
       return SECFailure;

    /* Keep track of negotiated extensions. */
    uint16ArrayAppend(&ss->xtnData.negotiated, ex_type);

    return SECSuccess;
}

static PRInt32
ssl3_ServerSendStatusRequestXtn(void *context, SSL_Socket *fd, PRBool append,
                                PRUint32 maxBytes)
{
    sslSocket *ss = ssl_UnpackSocket(fd);
    PORT_Assert(ss != NULL);

    PRInt32 extension_length;
    SECStatus rv;
    int i;
    PRBool haveStatus = PR_FALSE;

    for (i = kt_null; i < kt_kea_size; i++) {
	/* TODO: This is a temporary workaround.
	 *       The correct code needs to see if we have an OCSP response for
	 *       the server certificate being used, rather than if we have any
	 *       OCSP response. See also ssl3_SendCertificateStatus.
	 */
	if (ss->certStatusArray[i] && ss->certStatusArray[i]->len) {
	    haveStatus = PR_TRUE;
	    break;
	}
    }
    if (!haveStatus)
	return 0;

    extension_length = 2 + 2;
    if (append && maxBytes >= extension_length) {
	/* extension_type */
	rv = ssl3_AppendHandshakeNumber(ss, ssl_cert_status_xtn, 2);
	if (rv != SECSuccess)
	    return -1;
	/* length of extension_data */
	rv = ssl3_AppendHandshakeNumber(ss, 0, 2);
	if (rv != SECSuccess)
	    return -1;
    }

    return extension_length;
}

/* ssl3_ClientSendStatusRequestXtn builds the status_request extension on the
 * client side. See RFC 4366 section 3.6. */
static PRInt32
ssl3_ClientSendStatusRequestXtn(void *context, SSL_Socket *fd, PRBool append,
                                PRUint32 maxBytes)
{
    sslSocket *ss = ssl_UnpackSocket(fd);
    PORT_Assert(ss != NULL);

    PRInt32 extension_length;

    if (!ss->opt.enableOCSPStapling)
       return 0;

    /* extension_type (2-bytes) +
     * length(extension_data) (2-bytes) +
     * status_type (1) +
     * responder_id_list length (2) +
     * request_extensions length (2)
     */
    extension_length = 9;

    if (append && maxBytes >= extension_length) {
       SECStatus rv;
       TLSExtensionData *xtnData;

       /* extension_type */
       rv = ssl3_AppendHandshakeNumber(ss, ssl_cert_status_xtn, 2);
       if (rv != SECSuccess)
           return -1;
       rv = ssl3_AppendHandshakeNumber(ss, extension_length - 4, 2);
       if (rv != SECSuccess)
           return -1;
       rv = ssl3_AppendHandshakeNumber(ss, 1 /* status_type ocsp */, 1);
       if (rv != SECSuccess)
           return -1;
       /* A zero length responder_id_list means that the responders are
        * implicitly known to the server. */
       rv = ssl3_AppendHandshakeNumber(ss, 0, 2);
       if (rv != SECSuccess)
           return -1;
       /* A zero length request_extensions means that there are no extensions.
        * Specifically, we don't set the id-pkix-ocsp-nonce extension. This
        * means that the server can replay a cached OCSP response to us. */
       rv = ssl3_AppendHandshakeNumber(ss, 0, 2);
       if (rv != SECSuccess)
           return -1;

       xtnData = &ss->xtnData;
       uint16ArrayAppend(&xtnData->advertised, ssl_cert_status_xtn);
     } else if (maxBytes < extension_length) {
       PORT_Assert(0);
       return 0;
    }
    return extension_length;
}

/*
 * NewSessionTicket
 * Called from ssl3_HandleFinished
 */
SECStatus
ssl3_SendNewSessionTicket(sslSocket *ss)
{
    int                  i;
    SECStatus            rv;
    NewSessionTicket     ticket;
    SECItem              plaintext;
    SECItem              plaintext_item = {0, NULL, 0};
    SECItem              ciphertext     = {0, NULL, 0};
    PRUint32             ciphertext_length;
    PRBool               ms_is_wrapped;
    unsigned char        wrapped_ms[SSL3_MASTER_SECRET_LENGTH];
    SECItem              ms_item = {0, NULL, 0};
    SSL3KEAType          effectiveExchKeyType = ssl_kea_null;
    PRUint32             padding_length;
    PRUint32             message_length;
    PRUint32             cert_length;
    PRUint8              length_buf[4];
    PRUint32             now;
    PK11SymKey          *aes_key_pkcs11;
    PK11SymKey          *mac_key_pkcs11;
#ifndef NO_PKCS11_BYPASS
    const unsigned char *aes_key;
    const unsigned char *mac_key;
    PRUint32             aes_key_length;
    PRUint32             mac_key_length;
    PRUint64             aes_ctx_buf[MAX_CIPHER_CONTEXT_LLONGS];
    AESContext          *aes_ctx;
    const SECHashObject *hashObj = NULL;
    PRUint64             hmac_ctx_buf[MAX_MAC_CONTEXT_LLONGS];
    HMACContext         *hmac_ctx;
#endif
    CK_MECHANISM_TYPE    cipherMech = CKM_AES_CBC;
    PK11Context         *aes_ctx_pkcs11;
    CK_MECHANISM_TYPE    macMech = CKM_SHA256_HMAC;
    PK11Context         *hmac_ctx_pkcs11;
    unsigned char        computed_mac[TLS_EX_SESS_TICKET_MAC_LENGTH];
    unsigned int         computed_mac_length;
    unsigned char        iv[AES_BLOCK_SIZE];
    SECItem              ivItem;
    SECItem             *srvName = NULL;
    PRUint32             srvNameLen = 0;
    CK_MECHANISM_TYPE    msWrapMech = 0; /* dummy default value,
                                          * must be >= 0 */

    SSL_TRC(3, ("%d: SSL3[%d]: send session_ticket handshake",
		SSL_GETPID(), ss->fd));

    PORT_Assert( ss->opt.noLocks || ssl_HaveXmitBufLock(ss));
    PORT_Assert( ss->opt.noLocks || ssl_HaveSSL3HandshakeLock(ss));

    ticket.ticket_lifetime_hint = TLS_EX_SESS_TICKET_LIFETIME_HINT;
    cert_length = (ss->opt.requestCertificate && ss->sec.ci.sid->peerCert) ?
	3 + ss->sec.ci.sid->peerCert->derCert.len : 0;

    /* Get IV and encryption keys */
    ivItem.data = iv;
    ivItem.len = sizeof(iv);
    rv = PK11_GenerateRandom(iv, sizeof(iv));
    if (rv != SECSuccess) goto loser;

#ifndef NO_PKCS11_BYPASS
    if (ss->opt.bypassPKCS11) {
	rv = ssl3_GetSessionTicketKeys(&aes_key, &aes_key_length,
	    &mac_key, &mac_key_length);
    } else 
#endif
    {
	rv = ssl3_GetSessionTicketKeysPKCS11(ss, &aes_key_pkcs11,
	    &mac_key_pkcs11);
    }
    if (rv != SECSuccess) goto loser;

    if (ss->ssl3.pwSpec->msItem.len && ss->ssl3.pwSpec->msItem.data) {
	/* The master secret is available unwrapped. */
	ms_item.data = ss->ssl3.pwSpec->msItem.data;
	ms_item.len = ss->ssl3.pwSpec->msItem.len;
	ms_is_wrapped = PR_FALSE;
    } else {
	/* Extract the master secret wrapped. */
	sslSessionID sid;
	PORT_Memset(&sid, 0, sizeof(sslSessionID));

	if (ss->ssl3.hs.kea_def->kea == kea_ecdhe_rsa) {
	    effectiveExchKeyType = kt_rsa;
	} else {
	    effectiveExchKeyType = ss->ssl3.hs.kea_def->exchKeyType;
	}

	rv = ssl3_CacheWrappedMasterSecret(ss, &sid, ss->ssl3.pwSpec,
	    effectiveExchKeyType);
	if (rv == SECSuccess) {
	    if (sid.u.ssl3.keys.wrapped_master_secret_len > sizeof(wrapped_ms))
		goto loser;
	    memcpy(wrapped_ms, sid.u.ssl3.keys.wrapped_master_secret,
		sid.u.ssl3.keys.wrapped_master_secret_len);
	    ms_item.data = wrapped_ms;
	    ms_item.len = sid.u.ssl3.keys.wrapped_master_secret_len;
	    msWrapMech = sid.u.ssl3.masterWrapMech;
	} else {
	    /* TODO: else send an empty ticket. */
	    goto loser;
	}
	ms_is_wrapped = PR_TRUE;
    }
    /* Prep to send negotiated name */
    srvName = &ss->ssl3.pwSpec->srvVirtName;
    if (srvName->data && srvName->len) {
        srvNameLen = 2 + srvName->len; /* len bytes + name len */
    }

    ciphertext_length = 
	sizeof(PRUint16)                     /* ticket_version */
	+ sizeof(SSL3ProtocolVersion)        /* ssl_version */
	+ sizeof(ssl3CipherSuite)            /* ciphersuite */
	+ 1                                  /* compression */
	+ 10                                 /* cipher spec parameters */
	+ 1                                  /* SessionTicket.ms_is_wrapped */
	+ 1                                  /* effectiveExchKeyType */
	+ 4                                  /* msWrapMech */
	+ 2                                  /* master_secret.length */
	+ ms_item.len                        /* master_secret */
	+ 1                                  /* client_auth_type */
	+ cert_length                        /* cert */
        + 1                                  /* server name type */
        + srvNameLen                         /* name len + length field */
	+ sizeof(ticket.ticket_lifetime_hint);
    padding_length =  AES_BLOCK_SIZE -
	(ciphertext_length % AES_BLOCK_SIZE);
    ciphertext_length += padding_length;

    message_length =
	sizeof(ticket.ticket_lifetime_hint)    /* ticket_lifetime_hint */
	+ 2 /* length field for NewSessionTicket.ticket */
	+ SESS_TICKET_KEY_NAME_LEN             /* key_name */
	+ AES_BLOCK_SIZE                       /* iv */
	+ 2 /* length field for NewSessionTicket.ticket.encrypted_state */
	+ ciphertext_length                    /* encrypted_state */
	+ TLS_EX_SESS_TICKET_MAC_LENGTH;       /* mac */

    if (SECITEM_AllocItem(NULL, &plaintext_item, ciphertext_length) == NULL)
	goto loser;

    plaintext = plaintext_item;

    /* ticket_version */
    rv = ssl3_AppendNumberToItem(&plaintext, TLS_EX_SESS_TICKET_VERSION,
	sizeof(PRUint16));
    if (rv != SECSuccess) goto loser;

    /* ssl_version */
    rv = ssl3_AppendNumberToItem(&plaintext, ss->version,
	sizeof(SSL3ProtocolVersion));
    if (rv != SECSuccess) goto loser;

    /* ciphersuite */
    rv = ssl3_AppendNumberToItem(&plaintext, ss->ssl3.hs.cipher_suite, 
	sizeof(ssl3CipherSuite));
    if (rv != SECSuccess) goto loser;
    
    /* compression */
    rv = ssl3_AppendNumberToItem(&plaintext, ss->ssl3.hs.compression, 1);
    if (rv != SECSuccess) goto loser;

    /* cipher spec parameters */
    rv = ssl3_AppendNumberToItem(&plaintext, ss->sec.authAlgorithm, 1);
    if (rv != SECSuccess) goto loser;
    rv = ssl3_AppendNumberToItem(&plaintext, ss->sec.authKeyBits, 4);
    if (rv != SECSuccess) goto loser;
    rv = ssl3_AppendNumberToItem(&plaintext, ss->sec.keaType, 1);
    if (rv != SECSuccess) goto loser;
    rv = ssl3_AppendNumberToItem(&plaintext, ss->sec.keaKeyBits, 4);
    if (rv != SECSuccess) goto loser;

    /* master_secret */
    rv = ssl3_AppendNumberToItem(&plaintext, ms_is_wrapped, 1);
    if (rv != SECSuccess) goto loser;
    rv = ssl3_AppendNumberToItem(&plaintext, effectiveExchKeyType, 1);
    if (rv != SECSuccess) goto loser;
    rv = ssl3_AppendNumberToItem(&plaintext, msWrapMech, 4);
    if (rv != SECSuccess) goto loser;
    rv = ssl3_AppendNumberToItem(&plaintext, ms_item.len, 2);
    if (rv != SECSuccess) goto loser;
    rv = ssl3_AppendToItem(&plaintext, ms_item.data, ms_item.len);
    if (rv != SECSuccess) goto loser;

    /* client_identity */
    if (ss->opt.requestCertificate && ss->sec.ci.sid->peerCert) {
	rv = ssl3_AppendNumberToItem(&plaintext, CLIENT_AUTH_CERTIFICATE, 1);
	if (rv != SECSuccess) goto loser;
	rv = ssl3_AppendNumberToItem(&plaintext,
	    ss->sec.ci.sid->peerCert->derCert.len, 3);
	if (rv != SECSuccess) goto loser;
	rv = ssl3_AppendToItem(&plaintext,
	    ss->sec.ci.sid->peerCert->derCert.data,
	    ss->sec.ci.sid->peerCert->derCert.len);
	if (rv != SECSuccess) goto loser;
    } else {
	rv = ssl3_AppendNumberToItem(&plaintext, 0, 1);
	if (rv != SECSuccess) goto loser;
    }

    /* timestamp */
    now = ssl_Time();
    rv = ssl3_AppendNumberToItem(&plaintext, now,
	sizeof(ticket.ticket_lifetime_hint));
    if (rv != SECSuccess) goto loser;

    if (srvNameLen) {
        /* Name Type (sni_host_name) */
        rv = ssl3_AppendNumberToItem(&plaintext, srvName->type, 1);
        if (rv != SECSuccess) goto loser;
        /* HostName (length and value) */
        rv = ssl3_AppendNumberToItem(&plaintext, srvName->len, 2);
        if (rv != SECSuccess) goto loser;
        rv = ssl3_AppendToItem(&plaintext, srvName->data, srvName->len);
        if (rv != SECSuccess) goto loser;
    } else {
        /* No Name */
        rv = ssl3_AppendNumberToItem(&plaintext, (char)TLS_STE_NO_SERVER_NAME,
                                     1);
        if (rv != SECSuccess) goto loser;
    }

    PORT_Assert(plaintext.len == padding_length);
    for (i = 0; i < padding_length; i++)
	plaintext.data[i] = (unsigned char)padding_length;

    if (SECITEM_AllocItem(NULL, &ciphertext, ciphertext_length) == NULL) {
	rv = SECFailure;
	goto loser;
    }

    /* Generate encrypted portion of ticket. */
#ifndef NO_PKCS11_BYPASS
    if (ss->opt.bypassPKCS11) {
	aes_ctx = (AESContext *)aes_ctx_buf;
	rv = AES_InitContext(aes_ctx, aes_key, aes_key_length, iv, 
	    NSS_AES_CBC, 1, AES_BLOCK_SIZE);
	if (rv != SECSuccess) goto loser;

	rv = AES_Encrypt(aes_ctx, ciphertext.data, &ciphertext.len,
	    ciphertext.len, plaintext_item.data,
	    plaintext_item.len);
	if (rv != SECSuccess) goto loser;
    } else 
#endif
    {
	aes_ctx_pkcs11 = PK11_CreateContextBySymKey(cipherMech,
	    CKA_ENCRYPT, aes_key_pkcs11, &ivItem);
	if (!aes_ctx_pkcs11) 
	    goto loser;

	rv = PK11_CipherOp(aes_ctx_pkcs11, ciphertext.data,
	    (int *)&ciphertext.len, ciphertext.len,
	    plaintext_item.data, plaintext_item.len);
	PK11_Finalize(aes_ctx_pkcs11);
	PK11_DestroyContext(aes_ctx_pkcs11, PR_TRUE);
	if (rv != SECSuccess) goto loser;
    }

    /* Convert ciphertext length to network order. */
    length_buf[0] = (ciphertext.len >> 8) & 0xff;
    length_buf[1] = (ciphertext.len     ) & 0xff;

    /* Compute MAC. */
#ifndef NO_PKCS11_BYPASS
    if (ss->opt.bypassPKCS11) {
	hmac_ctx = (HMACContext *)hmac_ctx_buf;
	hashObj = HASH_GetRawHashObject(HASH_AlgSHA256);
	if (HMAC_Init(hmac_ctx, hashObj, mac_key,
		mac_key_length, PR_FALSE) != SECSuccess)
	    goto loser;

	HMAC_Begin(hmac_ctx);
	HMAC_Update(hmac_ctx, key_name, SESS_TICKET_KEY_NAME_LEN);
	HMAC_Update(hmac_ctx, iv, sizeof(iv));
	HMAC_Update(hmac_ctx, (unsigned char *)length_buf, 2);
	HMAC_Update(hmac_ctx, ciphertext.data, ciphertext.len);
	HMAC_Finish(hmac_ctx, computed_mac, &computed_mac_length,
	    sizeof(computed_mac));
    } else 
#endif
    {
	SECItem macParam;
	macParam.data = NULL;
	macParam.len = 0;
	hmac_ctx_pkcs11 = PK11_CreateContextBySymKey(macMech,
	    CKA_SIGN, mac_key_pkcs11, &macParam);
	if (!hmac_ctx_pkcs11)
	    goto loser;

	rv = PK11_DigestBegin(hmac_ctx_pkcs11);
	rv = PK11_DigestOp(hmac_ctx_pkcs11, key_name,
	    SESS_TICKET_KEY_NAME_LEN);
	rv = PK11_DigestOp(hmac_ctx_pkcs11, iv, sizeof(iv));
	rv = PK11_DigestOp(hmac_ctx_pkcs11, (unsigned char *)length_buf, 2);
	rv = PK11_DigestOp(hmac_ctx_pkcs11, ciphertext.data, ciphertext.len);
	rv = PK11_DigestFinal(hmac_ctx_pkcs11, computed_mac,
	    &computed_mac_length, sizeof(computed_mac));
	PK11_DestroyContext(hmac_ctx_pkcs11, PR_TRUE);
	if (rv != SECSuccess) goto loser;
    }

    /* Serialize the handshake message. */
    rv = ssl3_AppendHandshakeHeader(ss, new_session_ticket, message_length);
    if (rv != SECSuccess) goto loser;

    rv = ssl3_AppendHandshakeNumber(ss, ticket.ticket_lifetime_hint,
	sizeof(ticket.ticket_lifetime_hint));
    if (rv != SECSuccess) goto loser;

    rv = ssl3_AppendHandshakeNumber(ss,
	message_length - sizeof(ticket.ticket_lifetime_hint) - 2, 2);
    if (rv != SECSuccess) goto loser;

    rv = ssl3_AppendHandshake(ss, key_name, SESS_TICKET_KEY_NAME_LEN);
    if (rv != SECSuccess) goto loser;

    rv = ssl3_AppendHandshake(ss, iv, sizeof(iv));
    if (rv != SECSuccess) goto loser;

    rv = ssl3_AppendHandshakeVariable(ss, ciphertext.data, ciphertext.len, 2);
    if (rv != SECSuccess) goto loser;

    rv = ssl3_AppendHandshake(ss, computed_mac, computed_mac_length);
    if (rv != SECSuccess) goto loser;

loser:
    if (plaintext_item.data)
	SECITEM_FreeItem(&plaintext_item, PR_FALSE);
    if (ciphertext.data)
	SECITEM_FreeItem(&ciphertext, PR_FALSE);

    return rv;
}

/* When a client receives a SessionTicket extension a NewSessionTicket
 * message is expected during the handshake.
 */
SECStatus
ssl3_ClientHandleSessionTicketXtn(sslSocket *ss, PRUint16 ex_type,
                                  SECItem *data)
{
    if (data->len != 0)
	return SECFailure;

    /* Keep track of negotiated extensions. */
    uint16ArrayAppend(&ss->xtnData.negotiated, ex_type);
    return SECSuccess;
}

SECStatus
ssl3_ServerHandleSessionTicketXtn(sslSocket *ss, PRUint16 ex_type,
                                  SECItem *data)
{
    SECStatus rv;
    SECItem *decrypted_state = NULL;
    SessionTicket *parsed_session_ticket = NULL;
    sslSessionID *sid = NULL;
    SSL3Statistics *ssl3stats;

    /* Ignore the SessionTicket extension if processing is disabled. */
    if (!ss->opt.enableSessionTickets)
	return SECSuccess;

    /* Keep track of negotiated extensions. */
    uint16ArrayAppend(&ss->xtnData.negotiated, ex_type);

    /* Parse the received ticket sent in by the client.  We are
     * lenient about some parse errors, falling back to a fullshake
     * instead of terminating the current connection.
     */
    if (data->len == 0) {
	ss->xtnData.emptySessionTicket = PR_TRUE;
    } else {
	int                    i;
	SECItem                extension_data;
	EncryptedSessionTicket enc_session_ticket;
	unsigned char          computed_mac[TLS_EX_SESS_TICKET_MAC_LENGTH];
	unsigned int           computed_mac_length;
#ifndef NO_PKCS11_BYPASS
	const SECHashObject   *hashObj;
	const unsigned char   *aes_key;
	const unsigned char   *mac_key;
	PRUint32               aes_key_length;
	PRUint32               mac_key_length;
	PRUint64               hmac_ctx_buf[MAX_MAC_CONTEXT_LLONGS];
	HMACContext           *hmac_ctx;
	PRUint64               aes_ctx_buf[MAX_CIPHER_CONTEXT_LLONGS];
	AESContext            *aes_ctx;
#endif
	PK11SymKey            *aes_key_pkcs11;
	PK11SymKey            *mac_key_pkcs11;
	PK11Context           *hmac_ctx_pkcs11;
	CK_MECHANISM_TYPE      macMech = CKM_SHA256_HMAC;
	PK11Context           *aes_ctx_pkcs11;
	CK_MECHANISM_TYPE      cipherMech = CKM_AES_CBC;
	unsigned char *        padding;
	PRUint32               padding_length;
	unsigned char         *buffer;
	unsigned int           buffer_len;
	PRInt32                temp;
	SECItem                cert_item;
        PRInt8                 nameType = TLS_STE_NO_SERVER_NAME;

	/* Turn off stateless session resumption if the client sends a
	 * SessionTicket extension, even if the extension turns out to be
	 * malformed (ss->sec.ci.sid is non-NULL when doing session
	 * renegotiation.)
	 */
	if (ss->sec.ci.sid != NULL) {
	    if (ss->sec.uncache)
		ss->sec.uncache(ss->sec.ci.sid);
	    ssl_FreeSID(ss->sec.ci.sid);
	    ss->sec.ci.sid = NULL;
	}

	extension_data.data = data->data; /* Keep a copy for future use. */
	extension_data.len = data->len;

	if (ssl3_ParseEncryptedSessionTicket(ss, data, &enc_session_ticket)
	    != SECSuccess)
	    return SECFailure;

	/* Get session ticket keys. */
#ifndef NO_PKCS11_BYPASS
	if (ss->opt.bypassPKCS11) {
	    rv = ssl3_GetSessionTicketKeys(&aes_key, &aes_key_length,
		&mac_key, &mac_key_length);
	} else 
#endif
	{
	    rv = ssl3_GetSessionTicketKeysPKCS11(ss, &aes_key_pkcs11,
		&mac_key_pkcs11);
	}
	if (rv != SECSuccess) {
	    SSL_DBG(("%d: SSL[%d]: Unable to get/generate session ticket keys.",
			SSL_GETPID(), ss->fd));
	    goto loser;
	}

	/* If the ticket sent by the client was generated under a key different
	 * from the one we have, bypass ticket processing.
	 */
	if (PORT_Memcmp(enc_session_ticket.key_name, key_name,
		SESS_TICKET_KEY_NAME_LEN) != 0) {
	    SSL_DBG(("%d: SSL[%d]: Session ticket key_name sent mismatch.",
			SSL_GETPID(), ss->fd));
	    goto no_ticket;
	}

	/* Verify the MAC on the ticket.  MAC verification may also
	 * fail if the MAC key has been recently refreshed.
	 */
#ifndef NO_PKCS11_BYPASS
	if (ss->opt.bypassPKCS11) {
	    hmac_ctx = (HMACContext *)hmac_ctx_buf;
	    hashObj = HASH_GetRawHashObject(HASH_AlgSHA256);
	    if (HMAC_Init(hmac_ctx, hashObj, mac_key,
		    sizeof(session_ticket_mac_key), PR_FALSE) != SECSuccess)
		goto no_ticket;
	    HMAC_Begin(hmac_ctx);
	    HMAC_Update(hmac_ctx, extension_data.data,
		extension_data.len - TLS_EX_SESS_TICKET_MAC_LENGTH);
	    if (HMAC_Finish(hmac_ctx, computed_mac, &computed_mac_length,
		    sizeof(computed_mac)) != SECSuccess)
		goto no_ticket;
	} else 
#endif
	{
	    SECItem macParam;
	    macParam.data = NULL;
	    macParam.len = 0;
	    hmac_ctx_pkcs11 = PK11_CreateContextBySymKey(macMech,
		CKA_SIGN, mac_key_pkcs11, &macParam);
	    if (!hmac_ctx_pkcs11) {
		SSL_DBG(("%d: SSL[%d]: Unable to create HMAC context: %d.",
			    SSL_GETPID(), ss->fd, PORT_GetError()));
		goto no_ticket;
	    } else {
		SSL_DBG(("%d: SSL[%d]: Successfully created HMAC context.",
			    SSL_GETPID(), ss->fd));
	    }
	    rv = PK11_DigestBegin(hmac_ctx_pkcs11);
	    rv = PK11_DigestOp(hmac_ctx_pkcs11, extension_data.data,
		extension_data.len - TLS_EX_SESS_TICKET_MAC_LENGTH);
	    if (rv != SECSuccess) {
		PK11_DestroyContext(hmac_ctx_pkcs11, PR_TRUE);
		goto no_ticket;
	    }
	    rv = PK11_DigestFinal(hmac_ctx_pkcs11, computed_mac,
		&computed_mac_length, sizeof(computed_mac));
	    PK11_DestroyContext(hmac_ctx_pkcs11, PR_TRUE);
	    if (rv != SECSuccess)
		goto no_ticket;
	}
	if (NSS_SecureMemcmp(computed_mac, enc_session_ticket.mac,
		computed_mac_length) != 0) {
	    SSL_DBG(("%d: SSL[%d]: Session ticket MAC mismatch.",
			SSL_GETPID(), ss->fd));
	    goto no_ticket;
	}

	/* We ignore key_name for now.
	 * This is ok as MAC verification succeeded.
	 */

	/* Decrypt the ticket. */

	/* Plaintext is shorter than the ciphertext due to padding. */
	decrypted_state = SECITEM_AllocItem(NULL, NULL,
	    enc_session_ticket.encrypted_state.len);

#ifndef NO_PKCS11_BYPASS
	if (ss->opt.bypassPKCS11) {
	    aes_ctx = (AESContext *)aes_ctx_buf;
	    rv = AES_InitContext(aes_ctx, aes_key,
		sizeof(session_ticket_enc_key), enc_session_ticket.iv,
		NSS_AES_CBC, 0,AES_BLOCK_SIZE);
	    if (rv != SECSuccess) {
		SSL_DBG(("%d: SSL[%d]: Unable to create AES context.",
			    SSL_GETPID(), ss->fd));
		goto no_ticket;
	    }

	    rv = AES_Decrypt(aes_ctx, decrypted_state->data,
		&decrypted_state->len, decrypted_state->len,
		enc_session_ticket.encrypted_state.data,
		enc_session_ticket.encrypted_state.len);
	    if (rv != SECSuccess)
		goto no_ticket;
	} else 
#endif
	{
	    SECItem ivItem;
	    ivItem.data = enc_session_ticket.iv;
	    ivItem.len = AES_BLOCK_SIZE;
	    aes_ctx_pkcs11 = PK11_CreateContextBySymKey(cipherMech,
		CKA_DECRYPT, aes_key_pkcs11, &ivItem);
	    if (!aes_ctx_pkcs11) {
		SSL_DBG(("%d: SSL[%d]: Unable to create AES context.",
			    SSL_GETPID(), ss->fd));
		goto no_ticket;
	    }

	    rv = PK11_CipherOp(aes_ctx_pkcs11, decrypted_state->data,
		(int *)&decrypted_state->len, decrypted_state->len,
		enc_session_ticket.encrypted_state.data,
		enc_session_ticket.encrypted_state.len);
	    PK11_Finalize(aes_ctx_pkcs11);
	    PK11_DestroyContext(aes_ctx_pkcs11, PR_TRUE);
	    if (rv != SECSuccess)
		goto no_ticket;
	}

	/* Check padding. */
	padding_length = 
	    (PRUint32)decrypted_state->data[decrypted_state->len - 1];
	if (padding_length == 0 || padding_length > AES_BLOCK_SIZE)
	    goto no_ticket;

	padding = &decrypted_state->data[decrypted_state->len - padding_length];
	for (i = 0; i < padding_length; i++, padding++) {
	    if (padding_length != (PRUint32)*padding)
		goto no_ticket;
	}

	/* Deserialize session state. */
	buffer = decrypted_state->data;
	buffer_len = decrypted_state->len;

	parsed_session_ticket = PORT_ZAlloc(sizeof(SessionTicket));
	if (parsed_session_ticket == NULL) {
	    rv = SECFailure;
	    goto loser;
	}

	/* Read ticket_version (which is ignored for now.) */
	temp = ssl3_ConsumeHandshakeNumber(ss, 2, &buffer, &buffer_len);
	if (temp < 0) goto no_ticket;
	parsed_session_ticket->ticket_version = (SSL3ProtocolVersion)temp;

	/* Read SSLVersion. */
	temp = ssl3_ConsumeHandshakeNumber(ss, 2, &buffer, &buffer_len);
	if (temp < 0) goto no_ticket;
	parsed_session_ticket->ssl_version = (SSL3ProtocolVersion)temp;

	/* Read cipher_suite. */
	temp =  ssl3_ConsumeHandshakeNumber(ss, 2, &buffer, &buffer_len);
	if (temp < 0) goto no_ticket;
	parsed_session_ticket->cipher_suite = (ssl3CipherSuite)temp;

	/* Read compression_method. */
	temp = ssl3_ConsumeHandshakeNumber(ss, 1, &buffer, &buffer_len);
	if (temp < 0) goto no_ticket;
	parsed_session_ticket->compression_method = (SSLCompressionMethod)temp;

	/* Read cipher spec parameters. */
	temp = ssl3_ConsumeHandshakeNumber(ss, 1, &buffer, &buffer_len);
	if (temp < 0) goto no_ticket;
	parsed_session_ticket->authAlgorithm = (SSLSignType)temp;
	temp = ssl3_ConsumeHandshakeNumber(ss, 4, &buffer, &buffer_len);
	if (temp < 0) goto no_ticket;
	parsed_session_ticket->authKeyBits = (PRUint32)temp;
	temp = ssl3_ConsumeHandshakeNumber(ss, 1, &buffer, &buffer_len);
	if (temp < 0) goto no_ticket;
	parsed_session_ticket->keaType = (SSLKEAType)temp;
	temp = ssl3_ConsumeHandshakeNumber(ss, 4, &buffer, &buffer_len);
	if (temp < 0) goto no_ticket;
	parsed_session_ticket->keaKeyBits = (PRUint32)temp;

	/* Read wrapped master_secret. */
	temp = ssl3_ConsumeHandshakeNumber(ss, 1, &buffer, &buffer_len);
	if (temp < 0) goto no_ticket;
	parsed_session_ticket->ms_is_wrapped = (PRBool)temp;

	temp = ssl3_ConsumeHandshakeNumber(ss, 1, &buffer, &buffer_len);
	if (temp < 0) goto no_ticket;
	parsed_session_ticket->exchKeyType = (SSL3KEAType)temp;

	temp = ssl3_ConsumeHandshakeNumber(ss, 4, &buffer, &buffer_len);
	if (temp < 0) goto no_ticket;
	parsed_session_ticket->msWrapMech = (CK_MECHANISM_TYPE)temp;

	temp = ssl3_ConsumeHandshakeNumber(ss, 2, &buffer, &buffer_len);
	if (temp < 0) goto no_ticket;
	parsed_session_ticket->ms_length = (PRUint16)temp;
	if (parsed_session_ticket->ms_length == 0 ||  /* sanity check MS. */
	    parsed_session_ticket->ms_length >
	    sizeof(parsed_session_ticket->master_secret))
	    goto no_ticket;
	
	/* Allow for the wrapped master secret to be longer. */
	if (buffer_len < sizeof(SSL3_MASTER_SECRET_LENGTH))
	    goto no_ticket;
	PORT_Memcpy(parsed_session_ticket->master_secret, buffer,
	    parsed_session_ticket->ms_length);
	buffer += parsed_session_ticket->ms_length;
	buffer_len -= parsed_session_ticket->ms_length;

	/* Read client_identity */
	temp = ssl3_ConsumeHandshakeNumber(ss, 1, &buffer, &buffer_len);
	if (temp < 0)
	    goto no_ticket;
	parsed_session_ticket->client_identity.client_auth_type = 
	    (ClientAuthenticationType)temp;
	switch(parsed_session_ticket->client_identity.client_auth_type) {
            case CLIENT_AUTH_ANONYMOUS:
		break;
            case CLIENT_AUTH_CERTIFICATE:
		rv = ssl3_ConsumeHandshakeVariable(ss, &cert_item, 3,
		    &buffer, &buffer_len);
		if (rv != SECSuccess) goto no_ticket;
		rv = SECITEM_CopyItem(NULL, &parsed_session_ticket->peer_cert,
		    &cert_item);
		if (rv != SECSuccess) goto no_ticket;
		break;
            default:
		goto no_ticket;
	}
	/* Read timestamp. */
	temp = ssl3_ConsumeHandshakeNumber(ss, 4, &buffer, &buffer_len);
	if (temp < 0)
	    goto no_ticket;
	parsed_session_ticket->timestamp = (PRUint32)temp;

        /* Read server name */
        nameType =
                ssl3_ConsumeHandshakeNumber(ss, 1, &buffer, &buffer_len); 
        if (nameType != TLS_STE_NO_SERVER_NAME) {
            SECItem name_item;
            rv = ssl3_ConsumeHandshakeVariable(ss, &name_item, 2, &buffer,
                                               &buffer_len);
            if (rv != SECSuccess) goto no_ticket;
            rv = SECITEM_CopyItem(NULL, &parsed_session_ticket->srvName,
                                  &name_item);
            if (rv != SECSuccess) goto no_ticket;
            parsed_session_ticket->srvName.type = nameType;
        }

	/* Done parsing.  Check that all bytes have been consumed. */
	if (buffer_len != padding_length)
	    goto no_ticket;

	/* Use the ticket if it has not expired, otherwise free the allocated
	 * memory since the ticket is of no use.
	 */
	if (parsed_session_ticket->timestamp != 0 &&
	    parsed_session_ticket->timestamp +
	    TLS_EX_SESS_TICKET_LIFETIME_HINT > ssl_Time()) {

	    sid = ssl3_NewSessionID(ss, PR_TRUE);
	    if (sid == NULL) {
		rv = SECFailure;
		goto loser;
	    }

	    /* Copy over parameters. */
	    sid->version = parsed_session_ticket->ssl_version;
	    sid->u.ssl3.cipherSuite = parsed_session_ticket->cipher_suite;
	    sid->u.ssl3.compression = parsed_session_ticket->compression_method;
	    sid->authAlgorithm = parsed_session_ticket->authAlgorithm;
	    sid->authKeyBits = parsed_session_ticket->authKeyBits;
	    sid->keaType = parsed_session_ticket->keaType;
	    sid->keaKeyBits = parsed_session_ticket->keaKeyBits;

	    /* Copy master secret. */
#ifndef NO_PKCS11_BYPASS
	    if (ss->opt.bypassPKCS11 &&
		    parsed_session_ticket->ms_is_wrapped)
		goto no_ticket;
#endif
	    if (parsed_session_ticket->ms_length >
		    sizeof(sid->u.ssl3.keys.wrapped_master_secret))
		goto no_ticket;
	    PORT_Memcpy(sid->u.ssl3.keys.wrapped_master_secret,
		parsed_session_ticket->master_secret,
		parsed_session_ticket->ms_length);
	    sid->u.ssl3.keys.wrapped_master_secret_len =
		parsed_session_ticket->ms_length;
	    sid->u.ssl3.exchKeyType = parsed_session_ticket->exchKeyType;
	    sid->u.ssl3.masterWrapMech = parsed_session_ticket->msWrapMech;
	    sid->u.ssl3.keys.msIsWrapped =
		parsed_session_ticket->ms_is_wrapped;
	    sid->u.ssl3.masterValid    = PR_TRUE;
	    sid->u.ssl3.keys.resumable = PR_TRUE;

	    /* Copy over client cert from session ticket if there is one. */
	    if (parsed_session_ticket->peer_cert.data != NULL) {
		if (sid->peerCert != NULL)
		    CERT_DestroyCertificate(sid->peerCert);
		sid->peerCert = CERT_NewTempCertificate(ss->dbHandle,
		    &parsed_session_ticket->peer_cert, NULL, PR_FALSE, PR_TRUE);
		if (sid->peerCert == NULL) {
		    rv = SECFailure;
		    goto loser;
		}
	    }
	    if (parsed_session_ticket->srvName.data != NULL) {
                sid->u.ssl3.srvName = parsed_session_ticket->srvName;
            }
	    ss->statelessResume = PR_TRUE;
	    ss->sec.ci.sid = sid;
	}
    }

    if (0) {
no_ticket:
	SSL_DBG(("%d: SSL[%d]: Session ticket parsing failed.",
			SSL_GETPID(), ss->fd));
	ssl3stats = SSL_GetStatistics();
	SSL_AtomicIncrementLong(& ssl3stats->hch_sid_ticket_parse_failures );
    }
    rv = SECSuccess;

loser:
	/* ss->sec.ci.sid == sid if it did NOT come here via goto statement
	 * in that case do not free sid
	 */
	if (sid && (ss->sec.ci.sid != sid)) {
	    ssl_FreeSID(sid);
	    sid = NULL;
	}
    if (decrypted_state != NULL) {
	SECITEM_FreeItem(decrypted_state, PR_TRUE);
	decrypted_state = NULL;
    }

    if (parsed_session_ticket != NULL) {
	if (parsed_session_ticket->peer_cert.data) {
	    SECITEM_FreeItem(&parsed_session_ticket->peer_cert, PR_FALSE);
	}
	PORT_ZFree(parsed_session_ticket, sizeof(SessionTicket));
    }

    return rv;
}

/*
 * Read bytes.  Using this function means the SECItem structure
 * cannot be freed.  The caller is expected to call this function
 * on a shallow copy of the structure.
 */
static SECStatus 
ssl3_ConsumeFromItem(SECItem *item, unsigned char **buf, PRUint32 bytes)
{
    if (bytes > item->len)
	return SECFailure;

    *buf = item->data;
    item->data += bytes;
    item->len -= bytes;
    return SECSuccess;
}

static SECStatus
ssl3_ParseEncryptedSessionTicket(sslSocket *ss, SECItem *data,
                                 EncryptedSessionTicket *enc_session_ticket)
{
    if (ssl3_ConsumeFromItem(data, &enc_session_ticket->key_name,
	    SESS_TICKET_KEY_NAME_LEN) != SECSuccess)
	return SECFailure;
    if (ssl3_ConsumeFromItem(data, &enc_session_ticket->iv,
	    AES_BLOCK_SIZE) != SECSuccess)
	return SECFailure;
    if (ssl3_ConsumeHandshakeVariable(ss, &enc_session_ticket->encrypted_state,
	    2, &data->data, &data->len) != SECSuccess)
	return SECFailure;
    if (ssl3_ConsumeFromItem(data, &enc_session_ticket->mac,
	    TLS_EX_SESS_TICKET_MAC_LENGTH) != SECSuccess)
	return SECFailure;
    if (data->len != 0)  /* Make sure that we have consumed all bytes. */
	return SECFailure;

    return SECSuccess;
}

/* go through hello extensions in buffer "b".
 * For each one, find the extension handler in the table, and 
 * if present, invoke that handler.  
 * Servers ignore any extensions with unknown extension types.
 * Clients reject any extensions with unadvertised extension types.
 */
SECStatus 
ssl3_HandleHelloExtensions(sslSocket *ss, SSL3Opaque **b, PRUint32 *length)
{
    ssl3HelloExtensionHandlerCollection *handlers;

    if (ss->sec.isServer) {
        handlers = &clientHelloHandlers;
    } else if (ss->version > SSL_LIBRARY_VERSION_3_0) {
        handlers = &serverHelloHandlersTLS;
    } else {
        handlers = &serverHelloHandlersSSL3;
    }

    while (*length) {
	SECStatus rv;
	PRInt32   extension_type;
	SECItem   extension_data;

	/* Get the extension's type field */
	extension_type = ssl3_ConsumeHandshakeNumber(ss, 2, b, length);
	if (extension_type < 0)  /* failure to decode extension_type */
	    return SECFailure;   /* alert already sent */

	/* get the data for this extension, so we can pass it or skip it. */
	rv = ssl3_ConsumeHandshakeVariable(ss, &extension_data, 2, b, length);
	if (rv != SECSuccess)
	    return rv;

	/* Check whether the server sent an extension which was not advertised
	 * in the ClientHello.
	 */
	if (!ss->sec.isServer &&
	    !ssl3_ClientExtensionAdvertised(ss, extension_type))
	    return SECFailure;  /* TODO: send unsupported_extension alert */

	/* Check whether an extension has been sent multiple times. */
	if (ssl3_ExtensionNegotiated(ss, extension_type))
	    return SECFailure;

	/* find extension_type in table of Hello Extension Handlers */
  ssl3HelloExtensionHandlerCollectionIterator iter;
	for (hello_extension_collection_iterator(&iter, handlers);
       hello_extension_collection_iterator_has_next(&iter); ) {
      ssl3AbstractHelloExtensionHandler handler;
      hello_extension_collection_iterator_pop(&handler, &iter);
	    /* if found, call this handler */
	    if (abstract_extension_handler_ex_type(&handler) == extension_type) {
          rv = abstract_extension_handler_call(&handler, ss, (PRUint16)extension_type,
                                               &extension_data);
		/* Ignore this result */
		/* Treat all bad extensions as unrecognized types. */
	        break;
	    }
	}
    }
    return SECSuccess;
}

/* Add a callback function to the table of senders of server hello extensions.
 */
SECStatus 
ssl3_RegisterServerHelloExtensionSender(void *context, sslSocket *ss, PRUint16 ex_type,
				        SSL_HelloExtensionSenderFunc cb)
{
    int i;
    ssl3HelloExtensionSender *sender = &ss->xtnData.serverSenders.senders[0];

    for (i = 0; i < ss->xtnData.serverSenders.len; ++i, ++sender) {
	/* detect duplicate senders */
	PORT_Assert(sender->ex_type != ex_type);
	if (sender->ex_type == ex_type) {
	    /* duplicate */
    PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
    return SECFailure;
	}
    }
    ssl3HelloExtensionSender new_sender;
    new_sender.ex_type   = ex_type;
    new_sender.ex_sender = cb;
    new_sender.context = context;
    ssl3_ExtensionSenderCollectionEnsureInited(&ss->xtnData.serverSenders, NULL, 0);
    ssl3_ExtensionSenderCollectionAppend(&ss->xtnData.serverSenders, &new_sender);
    return SECSuccess;
}

/* call each of the extension senders and return the accumulated length */
PRInt32
ssl3_CallHelloExtensionSenders(sslSocket *ss, PRBool append, PRUint32 maxBytes,
                               const ssl3HelloSenderCollection *senders)
{
    PRInt32 total_exten_len = 0;
    int i;

    if (!senders) {
        if (ss->version > SSL_LIBRARY_VERSION_3_0) {
            ssl3_ExtensionSenderCollectionEnsureInited(&clientHelloSendersTLS,
                                                       builtinClientHelloSendersTLS,
                                                       sizeof(builtinClientHelloSendersTLS));
            senders = &clientHelloSendersTLS;
        } else {
            ssl3_ExtensionSenderCollectionEnsureInited(&clientHelloSendersSSL3,
                                                       builtinClientHelloSendersSSL3,
                                                       sizeof(builtinClientHelloSendersSSL3));

            senders = &clientHelloSendersSSL3;
        }
    }

    ssl3HelloExtensionSender *sender = &senders->senders[0];

    for (i = 0; i < senders->len; ++i, ++sender) {
	if (sender->ex_sender) {
	    PRInt32 extLen = (*sender->ex_sender)(sender->context, ssl_EncapsulateSocket(ss), append, maxBytes);
	    if (extLen < 0)
	    	return -1;
	    maxBytes        -= extLen;
	    total_exten_len += extLen;
	}
    }
    return total_exten_len;
}


/* Extension format:
 * Extension number:   2 bytes
 * Extension length:   2 bytes
 * Verify Data Length: 1 byte
 * Verify Data (TLS): 12 bytes (client) or 24 bytes (server)
 * Verify Data (SSL): 36 bytes (client) or 72 bytes (server)
 */
static PRInt32 
ssl3_SendRenegotiationInfoXtn(void *context, SSL_Socket *fd, PRBool append,
                       PRUint32 maxBytes)
{
    sslSocket *ss = ssl_UnpackSocket(fd);
    PORT_Assert(ss != NULL);

    PRInt32 len, needed;

    /* In draft-ietf-tls-renegotiation-03, it is NOT RECOMMENDED to send
     * both the SCSV and the empty RI, so when we send SCSV in 
     * the initial handshake, we don't also send RI.
     */
    if (!ss || ss->ssl3.hs.sendingSCSV)
    	return 0;
    len = !ss->firstHsDone ? 0 : 
	   (ss->sec.isServer ? ss->ssl3.hs.finishedBytes * 2 
			     : ss->ssl3.hs.finishedBytes);
    needed = 5 + len;
    if (append && maxBytes >= needed) {
	SECStatus rv;
	/* extension_type */
	rv = ssl3_AppendHandshakeNumber(ss, ssl_renegotiation_info_xtn, 2); 
	if (rv != SECSuccess) return -1;
	/* length of extension_data */
	rv = ssl3_AppendHandshakeNumber(ss, len + 1, 2); 
	if (rv != SECSuccess) return -1;
	/* verify_Data from previous Finished message(s) */
	rv = ssl3_AppendHandshakeVariable(ss, 
		  ss->ssl3.hs.finishedMsgs.data, len, 1);
	if (rv != SECSuccess) return -1;
	if (!ss->sec.isServer) {
	    TLSExtensionData *xtnData = &ss->xtnData;
	    uint16ArrayAppend(&xtnData->advertised, ssl_renegotiation_info_xtn);
	}
    }
    return needed;
}

static SECStatus
ssl3_ServerHandleStatusRequestXtn(sslSocket *ss, PRUint16 ex_type,
				  SECItem *data)
{
    SECStatus rv = SECSuccess;

    /* remember that we got this extension. */
    uint16ArrayAppend(&ss->xtnData.negotiated, ex_type);
    PORT_Assert(ss->sec.isServer);
    /* prepare to send back the appropriate response */
    rv = ssl3_RegisterServerHelloExtensionSender(NULL, ss, ex_type,
					    ssl3_ServerSendStatusRequestXtn);
    return rv;
}

/* This function runs in both the client and server.  */
static SECStatus
ssl3_HandleRenegotiationInfoXtn(sslSocket *ss, PRUint16 ex_type, SECItem *data)
{
    SECStatus rv = SECSuccess;
    PRUint32 len = 0;

    if (ss->firstHsDone) {
	len = ss->sec.isServer ? ss->ssl3.hs.finishedBytes 
	                       : ss->ssl3.hs.finishedBytes * 2;
    }
    if (data->len != 1 + len  ||
	data->data[0] != len  || (len && 
	NSS_SecureMemcmp(ss->ssl3.hs.finishedMsgs.data,
	                 data->data + 1, len))) {
	/* Can we do this here? Or, must we arrange for the caller to do it? */     
	(void)SSL3_SendAlert(ss, alert_fatal, handshake_failure);                   
	PORT_SetError(SSL_ERROR_BAD_HANDSHAKE_HASH_VALUE);
	return SECFailure;
    }
    /* remember that we got this extension and it was correct. */
    ss->peerRequestedProtection = 1;
    uint16ArrayAppend(&ss->xtnData.negotiated, ex_type);
    if (ss->sec.isServer) {
	/* prepare to send back the appropriate response */
        rv = ssl3_RegisterServerHelloExtensionSender(NULL, ss, ex_type,
					     ssl3_SendRenegotiationInfoXtn);
    }
    return rv;
}

static PRInt32
ssl3_SendUseSRTPXtn(void *context, SSL_Socket *fd, PRBool append,
                    PRUint32 maxBytes)
{
    sslSocket *ss = ssl_UnpackSocket(fd);
    PORT_Assert(ss != NULL);

    PRUint32 ext_data_len;
    PRInt16 i;
    SECStatus rv;

    if (!ss)
	return 0;

    if (!ss->sec.isServer) {
	/* Client side */

	if (!IS_DTLS(ss) || !ss->ssl3.dtlsSRTPCipherCount)
	    return 0;  /* Not relevant */

	ext_data_len = 2 + 2 * ss->ssl3.dtlsSRTPCipherCount + 1;

	if (append && maxBytes >= 4 + ext_data_len) {
	    /* Extension type */
	    rv = ssl3_AppendHandshakeNumber(ss, ssl_use_srtp_xtn, 2);
	    if (rv != SECSuccess) return -1;
	    /* Length of extension data */
	    rv = ssl3_AppendHandshakeNumber(ss, ext_data_len, 2);
	    if (rv != SECSuccess) return -1;
	    /* Length of the SRTP cipher list */
	    rv = ssl3_AppendHandshakeNumber(ss,
					    2 * ss->ssl3.dtlsSRTPCipherCount,
					    2);
	    if (rv != SECSuccess) return -1;
	    /* The SRTP ciphers */
	    for (i = 0; i < ss->ssl3.dtlsSRTPCipherCount; i++) {
		rv = ssl3_AppendHandshakeNumber(ss,
						ss->ssl3.dtlsSRTPCiphers[i],
						2);
	    }
	    /* Empty MKI value */
	    ssl3_AppendHandshakeVariable(ss, NULL, 0, 1);

	    uint16ArrayAppend(&ss->xtnData.advertised, ssl_use_srtp_xtn);
	}

	return 4 + ext_data_len;
    }

    /* Server side */
    if (append && maxBytes >= 9) {
	/* Extension type */
	rv = ssl3_AppendHandshakeNumber(ss, ssl_use_srtp_xtn, 2);
	if (rv != SECSuccess) return -1;
	/* Length of extension data */
	rv = ssl3_AppendHandshakeNumber(ss, 5, 2);
	if (rv != SECSuccess) return -1;
	/* Length of the SRTP cipher list */
	rv = ssl3_AppendHandshakeNumber(ss, 2, 2);
	if (rv != SECSuccess) return -1;
	/* The selected cipher */
	rv = ssl3_AppendHandshakeNumber(ss, ss->ssl3.dtlsSRTPCipherSuite, 2);
	if (rv != SECSuccess) return -1;
	/* Empty MKI value */
	ssl3_AppendHandshakeVariable(ss, NULL, 0, 1);
    }

    return 9;
}

static SECStatus
ssl3_HandleUseSRTPXtn(sslSocket * ss, PRUint16 ex_type, SECItem *data)
{
    SECStatus rv;
    SECItem ciphers = {siBuffer, NULL, 0};
    PRUint16 i;
    unsigned int j;
    PRUint16 cipher = 0;
    PRBool found = PR_FALSE;
    SECItem litem;

    if (!ss->sec.isServer) {
	/* Client side */
	if (!data->data || !data->len) {
            /* malformed */
            return SECFailure;
	}

	/* Get the cipher list */
	rv = ssl3_ConsumeHandshakeVariable(ss, &ciphers, 2,
					   &data->data, &data->len);
	if (rv != SECSuccess) {
	    return SECFailure;
	}
	/* Now check that the number of ciphers listed is 1 (len = 2) */
	if (ciphers.len != 2) {
	    return SECFailure;
	}

	/* Get the selected cipher */
	cipher = (ciphers.data[0] << 8) | ciphers.data[1];

	/* Now check that this is one of the ciphers we offered */
	for (i = 0; i < ss->ssl3.dtlsSRTPCipherCount; i++) {
	    if (cipher == ss->ssl3.dtlsSRTPCiphers[i]) {
		found = PR_TRUE;
		break;
	    }
	}

	if (!found) {
	    return SECFailure;
	}

	/* Get the srtp_mki value */
        rv = ssl3_ConsumeHandshakeVariable(ss, &litem, 1,
					   &data->data, &data->len);
        if (rv != SECSuccess) {
            return SECFailure;
        }

	/* We didn't offer an MKI, so this must be 0 length */
	/* XXX RFC 5764 Section 4.1.3 says:
	 *   If the client detects a nonzero-length MKI in the server's
	 *   response that is different than the one the client offered,
	 *   then the client MUST abort the handshake and SHOULD send an
	 *   invalid_parameter alert.
	 *
	 * Due to a limitation of the ssl3_HandleHelloExtensions function,
	 * returning SECFailure here won't abort the handshake.  It will
	 * merely cause the use_srtp extension to be not negotiated.  We
	 * should fix this.  See NSS bug 753136.
	 */
	if (litem.len != 0) {
	    return SECFailure;
	}

	if (data->len != 0) {
            /* malformed */
            return SECFailure;
	}

	/* OK, this looks fine. */
	uint16ArrayAppend(&ss->xtnData.negotiated, ssl_use_srtp_xtn);
	ss->ssl3.dtlsSRTPCipherSuite = cipher;
	return SECSuccess;
    }

    /* Server side */
    if (!IS_DTLS(ss) || !ss->ssl3.dtlsSRTPCipherCount) {
	/* Ignore the extension if we aren't doing DTLS or no DTLS-SRTP
	 * preferences have been set. */
	return SECSuccess;
    }

    if (!data->data || data->len < 5) {
	/* malformed */
	return SECFailure;
    }

    /* Get the cipher list */
    rv = ssl3_ConsumeHandshakeVariable(ss, &ciphers, 2,
				       &data->data, &data->len);
    if (rv != SECSuccess) {
	return SECFailure;
    }
    /* Check that the list is even length */
    if (ciphers.len % 2) {
	return SECFailure;
    }

    /* Walk through the offered list and pick the most preferred of our
     * ciphers, if any */
    for (i = 0; !found && i < ss->ssl3.dtlsSRTPCipherCount; i++) {
	for (j = 0; j + 1 < ciphers.len; j += 2) {
	    cipher = (ciphers.data[j] << 8) | ciphers.data[j + 1];
	    if (cipher == ss->ssl3.dtlsSRTPCiphers[i]) {
		found = PR_TRUE;
		break;
	    }
	}
    }

    /* Get the srtp_mki value */
    rv = ssl3_ConsumeHandshakeVariable(ss, &litem, 1, &data->data, &data->len);
    if (rv != SECSuccess) {
	return SECFailure;
    }

    if (data->len != 0) {
	return SECFailure; /* Malformed */
    }

    /* Now figure out what to do */
    if (!found) {
	/* No matching ciphers */
	return SECSuccess;
    }

    /* OK, we have a valid cipher and we've selected it */
    ss->ssl3.dtlsSRTPCipherSuite = cipher;
    uint16ArrayAppend(&ss->xtnData.negotiated, ssl_use_srtp_xtn);

    return ssl3_RegisterServerHelloExtensionSender(NULL, ss, ssl_use_srtp_xtn,
						   ssl3_SendUseSRTPXtn);
}

/* ssl3_ServerHandleSigAlgsXtn handles the signature_algorithms extension
 * from a client.
 * See https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1 */
static SECStatus
ssl3_ServerHandleSigAlgsXtn(sslSocket * ss, PRUint16 ex_type, SECItem *data)
{
    SECStatus rv;
    SECItem algorithms;
    const unsigned char *b;
    unsigned int numAlgorithms, i;

    /* Ignore this extension if we aren't doing TLS 1.2 or greater. */
    if (ss->version < SSL_LIBRARY_VERSION_TLS_1_2) {
	return SECSuccess;
    }

    /* Keep track of negotiated extensions. */
    uint16ArrayAppend(&ss->xtnData.negotiated, ex_type);

    rv = ssl3_ConsumeHandshakeVariable(ss, &algorithms, 2, &data->data,
				       &data->len);
    if (rv != SECSuccess) {
	return SECFailure;
    }
    /* Trailing data, empty value, or odd-length value is invalid. */
    if (data->len != 0 || algorithms.len == 0 || (algorithms.len & 1) != 0) {
	PORT_SetError(SSL_ERROR_RX_MALFORMED_CLIENT_HELLO);
	return SECFailure;
    }

    numAlgorithms = algorithms.len/2;

    /* We don't care to process excessive numbers of algorithms. */
    if (numAlgorithms > 512) {
	numAlgorithms = 512;
    }

    ss->ssl3.hs.clientSigAndHash =
	    PORT_NewArray(SSL3SignatureAndHashAlgorithm, numAlgorithms);
    if (!ss->ssl3.hs.clientSigAndHash) {
	return SECFailure;
    }
    ss->ssl3.hs.numClientSigAndHash = 0;

    b = algorithms.data;
    for (i = 0; i < numAlgorithms; i++) {
	unsigned char tls_hash = *(b++);
	unsigned char tls_sig = *(b++);
	SECOidTag hash = ssl3_TLSHashAlgorithmToOID(tls_hash);

	if (hash == SEC_OID_UNKNOWN) {
	    /* We ignore formats that we don't understand. */
	    continue;
	}
	/* tls_sig support will be checked later in
	 * ssl3_PickSignatureHashAlgorithm. */
	ss->ssl3.hs.clientSigAndHash[i].hashAlg = hash;
	ss->ssl3.hs.clientSigAndHash[i].sigAlg = tls_sig;
	ss->ssl3.hs.numClientSigAndHash++;
    }

    if (!ss->ssl3.hs.numClientSigAndHash) {
	/* We didn't understand any of the client's requested signature
	 * formats. We'll use the defaults. */
	PORT_Free(ss->ssl3.hs.clientSigAndHash);
	ss->ssl3.hs.clientSigAndHash = NULL;
    }

    return SECSuccess;
}

/* ssl3_ClientSendSigAlgsXtn sends the signature_algorithm extension for TLS
 * 1.2 ClientHellos. */
static PRInt32
ssl3_ClientSendSigAlgsXtn(void *context, SSL_Socket *fd, PRBool append,
                                PRUint32 maxBytes)
{
    sslSocket *ss = ssl_UnpackSocket(fd);
    PORT_Assert(ss != NULL);

    static const unsigned char signatureAlgorithms[] = {
	/* This block is the contents of our signature_algorithms extension, in
	 * wire format. See
	 * https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1 */
	tls_hash_sha256, tls_sig_rsa,
	tls_hash_sha384, tls_sig_rsa,
	tls_hash_sha1,   tls_sig_rsa,
#ifdef NSS_ENABLE_ECC
	tls_hash_sha256, tls_sig_ecdsa,
	tls_hash_sha384, tls_sig_ecdsa,
	tls_hash_sha1,   tls_sig_ecdsa,
#endif
	tls_hash_sha256, tls_sig_dsa,
	tls_hash_sha1,   tls_sig_dsa,
    };
    PRInt32 extension_length;

    if (ss->version < SSL_LIBRARY_VERSION_TLS_1_2) {
	return 0;
    }

    extension_length =
	2 /* extension type */ +
	2 /* extension length */ +
	2 /* supported_signature_algorithms length */ +
	sizeof(signatureAlgorithms);

    if (append && maxBytes >= extension_length) {
	SECStatus rv;
	rv = ssl3_AppendHandshakeNumber(ss, ssl_signature_algorithms_xtn, 2);
	if (rv != SECSuccess)
	    goto loser;
	rv = ssl3_AppendHandshakeNumber(ss, extension_length - 4, 2);
	if (rv != SECSuccess)
	    goto loser;
	rv = ssl3_AppendHandshakeVariable(ss, signatureAlgorithms,
					  sizeof(signatureAlgorithms), 2);
	if (rv != SECSuccess)
	    goto loser;
	uint16ArrayAppend(&ss->xtnData.advertised, ssl_signature_algorithms_xtn);
    } else if (maxBytes < extension_length) {
	PORT_Assert(0);
	return 0;
    }

    return extension_length;

loser:
    return -1;
}


/* Initialization needed for this file.
   Should only be called by ssl_Init. */
void
ssl3_ExtInit() {
    hello_extension_collection_init(&serverHelloHandlersTLS);
    hello_extension_collection_init(&serverHelloHandlersSSL3);
}


// TODO put these functions in appropriate header and in the .def file.

SECStatus
SSL_AppendHandshake(PRFileDesc *fd, const void *void_src,
                    PRInt32 bytes) {
    sslSocket *ss = ssl_UnpackSocket(fd);
    PORT_Assert(ss != NULL);

    return ssl3_AppendHandshake(ss, void_src, bytes);
}
SECStatus
SSL_AppendHandshakeHeader(PRFileDesc *fd,
                          SSL3HandshakeType t, PRUint32 length) {
    sslSocket *ss = ssl_UnpackSocket(fd);
    PORT_Assert(ss != NULL);

    return ssl3_AppendHandshakeHeader(ss, t, length);
}

SECStatus
SSL_AppendHandshakeNumber(PRFileDesc *fd, PRInt32 num, PRInt32 lenSize) {
    sslSocket *ss = ssl_UnpackSocket(fd);
    PORT_Assert(ss != NULL);

    return ssl3_AppendHandshakeNumber(ss, num, lenSize);
}
SECStatus
SSL_AppendHandshakeVariable(PRFileDesc *fd, const SSL3Opaque *src,
                            PRInt32 bytes, PRInt32 lenSize) {
    sslSocket *ss = ssl_UnpackSocket(fd);
    PORT_Assert(ss != NULL);

    return ssl3_AppendHandshakeVariable(ss, src, bytes, lenSize);
}

SECStatus
SSL_ConsumeHandshake(PRFileDesc *fd, void *v, PRInt32 bytes,
                     SSL3Opaque **b, PRUint32 *length) {
    sslSocket *ss = ssl_UnpackSocket(fd);
    PORT_Assert(ss != NULL);

    return ssl3_ConsumeHandshake(ss, v, bytes, b, length);
}
PRInt32
SSL_ConsumeHandshakeNumber(PRFileDesc *fd, PRInt32 bytes,
                           SSL3Opaque **b, PRUint32 *length) {
    sslSocket *ss = ssl_UnpackSocket(fd);
    PORT_Assert(ss != NULL);

    return ssl3_ConsumeHandshakeNumber(ss, bytes, b, length);
}
SECStatus
SSL_ConsumeHandshakeVariable(PRFileDesc *fd, SECItem *i, PRInt32 bytes,
                             SSL3Opaque **b, PRUint32 *length) {
    sslSocket *ss = ssl_UnpackSocket(fd);
    PORT_Assert(ss != NULL);

    return ssl3_ConsumeHandshakeVariable(fd, i, bytes, b, length);
}

/* Add support for a custom TLS extension when we are the client of
   a connection.
   - ex_type is the IANA number identifying the extension. (machine-byte order)
   - hello_sender will be called to append data to the ClientHello
   - sender_context will be passed to hello_sender
   - server_hello_handler will be provided the extension data from ServerHello
   - handler_context will be passed to server_hello_handler */
void
SSL_SetCustomClientHelloTLS(PRInt32 ex_type,
                            SSL_HelloExtensionSenderFunc hello_sender,
                            void *sender_context,
                            SSL_HelloExtensionHandlerFunc server_hello_handler,
                            void *handler_context) {
    ssl3HelloExtensionSender sender;
    sender.ex_type = ex_type;
    sender.ex_sender = hello_sender;
    sender.context = sender_context;
            ssl3_ExtensionSenderCollectionEnsureInited(&clientHelloSendersTLS,
                                                       builtinClientHelloSendersTLS,
                                                       sizeof(builtinClientHelloSendersTLS));

    ssl3_ExtensionSenderCollectionAppend(&clientHelloSendersTLS, &sender);

    ssl3CustomHelloExtensionHandler handler;
    handler.ex_type = ex_type;
    handler.ex_handler = server_hello_handler;
    handler.context = handler_context;
    hello_extension_collection_append(&serverHelloHandlersTLS, &handler);
}



/* Register a ServerHello extension sender for the TLS connection associated
   with fd.
 */
SECStatus SSL_RegisterServerHelloExtensionSender(void *context, SSL_Socket *fd,
                                                 PRUint16 ex_type,
                                                 SSL_HelloExtensionSenderFunc sender) {
    return ssl3_RegisterServerHelloExtensionSender(context, ssl_UnpackSocket(fd),
                                                   ex_type, sender);
}

/* Add support for a custom TLS extension when we are the server of a
   connection.
   - ex_type is the IANA number identifying the extension. (machine-byte order)
   - client_hello_handler will be called on receipt of a proper ClientHello extension
   - context will be passed to client_hello_handler.

   This does not register a Sender to send the ServerHello extension, as this is
   registered per-connection, rather than globally.
   client_hello_handler should call SSL_RegisterServerHelloExtensionSender when it
   wants to use the extension and thus respond with a ServerHello extension.
*/
void
SSL_SetCustomServerHello(PRInt32 ex_type, SSL_HelloExtensionHandlerFunc client_hello_handler,
                         void *context) {

    ssl3CustomHelloExtensionHandler *handler = PORT_Alloc(sizeof(*handler));
    handler->ex_type = ex_type;
    handler->ex_handler = client_hello_handler;
    handler->context = context;
    hello_extension_collection_append(&clientHelloHandlers, handler);
}
