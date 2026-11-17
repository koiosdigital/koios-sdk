// Device identity for Linux.
//
// The certificate is a PEM file (leaf first). The private key is whatever
// OpenSSL can open by name: a file, or a URI served by a provider. On a box
// whose key lives in a secure element or in OP-TEE that is a PKCS#11 URI, and
// what comes back is a handle: OpenSSL asks the provider to sign, the key
// never enters this process. The process must run with an OpenSSL
// configuration that loads the provider (OPENSSL_CONF).
//
// Nothing here ever asks a person for a PIN. A provider that asks for one is
// given an empty PIN, which is how a token that logs callers in by their
// identity (OP-TEE's) is opened.

#include "koios/port/kp_identity.h"
#include "koios/port/kp_os.h"
#include "koios/port/kp_log.h"
#include "kp_linux.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/store.h>
#include <openssl/ui.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char* TAG = "kp_identity";

bool kp_identity_ready(void) {
    const kp_linux_cfg_t* cfg = kp_linux_cfg();
    if (!cfg->cert_file || !cfg->key) return false;
    if (cfg->identity_ready_file && access(cfg->identity_ready_file, F_OK) != 0) return false;
    return access(cfg->cert_file, R_OK) == 0;
}

static STACK_OF(X509)* read_certs(const char* path) {
    BIO* bio = BIO_new_file(path, "r");
    if (!bio) return NULL;
    STACK_OF(X509)* certs = sk_X509_new_null();
    X509* cert;
    while (certs && (cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(certs, cert);
    }
    ERR_clear_error();  // reading past the last certificate ends in an error
    BIO_free(bio);
    return certs;
}

static bool contains(STACK_OF(X509)* certs, X509* cert) {
    for (int i = 0; i < sk_X509_num(certs); i++) {
        if (X509_cmp(sk_X509_value(certs, i), cert) == 0) return true;
    }
    return false;
}

// cert_file, then the certificates of extra_chain_file that are not in it
// yet, as one PEM. A self-signed certificate is left out: a root is never
// sent, the peer has its own.
int kp_identity_get_client_cert(char** pem, size_t* len) {
    *pem = NULL;
    *len = 0;
    const kp_linux_cfg_t* cfg = kp_linux_cfg();
    if (!cfg->cert_file) return -1;

    STACK_OF(X509)* chain = read_certs(cfg->cert_file);
    if (!chain || sk_X509_num(chain) == 0) {
        KP_LOGE(TAG, "no certificate in %s", cfg->cert_file);
        sk_X509_pop_free(chain, X509_free);
        return -1;
    }
    if (cfg->extra_chain_file) {
        STACK_OF(X509)* extra = read_certs(cfg->extra_chain_file);
        if (!extra) KP_LOGW(TAG, "cannot read %s", cfg->extra_chain_file);
        while (extra && sk_X509_num(extra) > 0) {
            X509* cert = sk_X509_shift(extra);
            const bool self_signed = X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) == 0;
            if (self_signed || contains(chain, cert) || !sk_X509_push(chain, cert)) X509_free(cert);
        }
        sk_X509_free(extra);
    }

    int rc = -1;
    BIO* out = BIO_new(BIO_s_mem());
    if (out) {
        bool ok = true;
        for (int i = 0; ok && i < sk_X509_num(chain); i++) {
            ok = PEM_write_bio_X509(out, sk_X509_value(chain, i)) == 1;
        }
        char* data = NULL;
        const long n = BIO_get_mem_data(out, &data);
        if (ok && n > 0) {
            char* copy = kp_malloc((size_t)n + 1);
            if (copy) {
                memcpy(copy, data, (size_t)n);
                copy[n] = '\0';
                *pem = copy;
                *len = (size_t)n;
                rc = 0;
            }
        }
        BIO_free(out);
    }
    sk_X509_pop_free(chain, X509_free);
    return rc;
}

//------------------------------------------------------------------------------
// The key
//------------------------------------------------------------------------------

// Answer every prompt with an empty string and never touch a terminal.
static int ui_read_empty(UI* ui, UI_STRING* uis) {
    switch (UI_get_string_type(uis)) {
    case UIT_PROMPT:
    case UIT_VERIFY:
        UI_set_result(ui, uis, "");
        return 1;
    default:
        return 1;
    }
}

static int ui_noop(UI* ui) { (void)ui; return 1; }
static int ui_write_noop(UI* ui, UI_STRING* uis) { (void)ui; (void)uis; return 1; }

static EVP_PKEY* load_key(const char* name) {
    static UI_METHOD* ui;
    if (!ui) {
        ui = UI_create_method("koios: no prompt");
        if (ui) {
            UI_method_set_opener(ui, ui_noop);
            UI_method_set_reader(ui, ui_read_empty);
            UI_method_set_writer(ui, ui_write_noop);
            UI_method_set_closer(ui, ui_noop);
        }
    }

    OSSL_STORE_CTX* store = OSSL_STORE_open_ex(name, NULL, NULL, ui, NULL, NULL, NULL, NULL);
    if (!store) return NULL;
    OSSL_STORE_expect(store, OSSL_STORE_INFO_PKEY);
    EVP_PKEY* pkey = NULL;
    while (!pkey && !OSSL_STORE_eof(store)) {
        OSSL_STORE_INFO* info = OSSL_STORE_load(store);
        if (!info) {
            if (OSSL_STORE_error(store)) break;
            continue;
        }
        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
            pkey = OSSL_STORE_INFO_get1_PKEY(info);
        }
        OSSL_STORE_INFO_free(info);
    }
    OSSL_STORE_close(store);
    return pkey;
}

void* kp_identity_get_key_ctx(void) {
    const kp_linux_cfg_t* cfg = kp_linux_cfg();
    if (!cfg->key) return NULL;

    ERR_clear_error();
    EVP_PKEY* pkey = load_key(cfg->key);
    if (!pkey) {
        char msg[200] = "no key found";
        const unsigned long err = ERR_peek_last_error();
        if (err) ERR_error_string_n(err, msg, sizeof(msg));
        // Name the key's kind, never its location in full: a URI may carry a PIN.
        KP_LOGE(TAG, "cannot open the identity key (%s): %s",
            strncmp(cfg->key, "pkcs11:", 7) == 0 ? "PKCS#11 URI" : "file", msg);
        return NULL;
    }

    kp_linux_key_ctx_t* ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    ctx->pkey = pkey;
    return ctx;
}

void kp_identity_release_key_ctx(void* opaque) {
    kp_linux_key_ctx_t* ctx = opaque;
    if (!ctx) return;
    EVP_PKEY_free(ctx->pkey);
    free(ctx);
}
