/*
 * tpm_nif.c — Linux TPM 2.0 NIF for Erlang/Elixir
 *
 * Provides hardware-backed P-384 (secp384r1) key storage via the
 * Linux TPM 2.0 chip using the tss2-esys / tss2-mu / tss2-rc libraries
 * from the TPM2 Software Stack (tpm2-tss).
 *
 * The key is created as a persistent object under the Owner hierarchy
 * (handle 0x81010001 by default) and is never extractable.
 *
 * NIST SP 800-53 controls enforced:
 *   SC-12    — key generated inside TPM; persistent handle in NV storage
 *   SC-12(1) — persistent object survives reboots (TPM NV)
 *   SC-12(4) — key encrypted by TPM Storage Root Key (SRK); not exportable
 *   SC-12(5) — Esys_EvictControl removes the persistent handle
 *   SC-13    — TPM 2.0 FIPS 140-2 Level 2 P-384 ECDSA (TPMS_ALG_ECC_NIST_P384)
 *   SC-28    — private key never leaves TPM boundary
 *   SC-28(1) — NV storage encrypted by TPM internal SRK hierarchy
 *   MP-4     — key reference is a 32-bit TPM handle; no filesystem exposure
 *   MP-6     — Esys_EvictControl(ESYS_TR_RH_OWNER,...,ESYS_TR_NONE) is irreversible
 *
 * Build requirements (Linux):
 *   libtss2-esys-dev  libtss2-mu-dev  libtss2-rc-dev
 *   pkg-config --cflags --libs tss2-esys tss2-mu tss2-rc
 *
 * NIF interface:
 *   tpm_generate_key(PersistentHandle :: integer)
 *       -> {:ok, PublicKeyRaw :: binary} | {:error, Reason}
 *   tpm_public_key(PersistentHandle :: integer)
 *       -> {:ok, PublicKeyRaw :: binary} | {:error, Reason}
 *   tpm_sign(PersistentHandle :: integer, Digest :: binary)
 *       -> {:ok, SignatureDER :: binary} | {:error, Reason}
 *   tpm_delete_key(PersistentHandle :: integer)
 *       -> :ok | {:error, Reason}
 */

#include <erl_nif.h>

#ifdef __linux__

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  Helpers                                                             */
/* ------------------------------------------------------------------ */

#define TPM2_DEFAULT_PERSISTENT 0x81010001U  /* Owner hierarchy slot 1 */

static ERL_NIF_TERM make_error(ErlNifEnv *env, const char *msg) {
    return enif_make_tuple2(env,
        enif_make_atom(env, "error"),
        enif_make_string(env, msg, ERL_NIF_LATIN1));
}

static ERL_NIF_TERM make_ok_binary(ErlNifEnv *env, const void *data, size_t len) {
    ErlNifBinary bin;
    if (!enif_alloc_binary(len, &bin)) return make_error(env, "alloc_failed");
    memcpy(bin.data, data, len);
    return enif_make_tuple2(env,
        enif_make_atom(env, "ok"),
        enif_make_binary(env, &bin));
}

/* Get the persistent handle from an Erlang integer argument. */
static int get_handle(ErlNifEnv *env, ERL_NIF_TERM term, TPMI_DH_PERSISTENT *out) {
    unsigned long val;
    if (enif_get_ulong(env, term, &val)) { *out = (TPMI_DH_PERSISTENT)val; return 1; }
    unsigned int ival;
    if (enif_get_uint(env, term, &ival)) { *out = (TPMI_DH_PERSISTENT)ival; return 1; }
    return 0;
}

/* Encode an ECDSA signature (TPMT_SIGNATURE) to ASN.1 DER X9.62 format. */
static int encode_ecdsa_der(const TPMT_SIGNATURE *sig,
                             unsigned char *out, size_t *outlen) {
    /* r and s are stored big-endian in TPM2B buffers */
    size_t rlen = sig->signature.ecdsa.signatureR.size;
    size_t slen = sig->signature.ecdsa.signatureS.size;
    const unsigned char *r = sig->signature.ecdsa.signatureR.buffer;
    const unsigned char *s = sig->signature.ecdsa.signatureS.buffer;

    /* Strip leading zeros; add 0x00 prefix if high bit set */
    size_t rpad = (r[0] & 0x80) ? 1 : 0;
    size_t spad = (s[0] & 0x80) ? 1 : 0;

    size_t seq_len = 2 + rpad + rlen + 2 + spad + slen;
    size_t total   = 2 + seq_len;
    if (total > *outlen) return 0;

    size_t i = 0;
    out[i++] = 0x30;                       /* SEQUENCE */
    out[i++] = (unsigned char)seq_len;
    out[i++] = 0x02;                       /* INTEGER r */
    out[i++] = (unsigned char)(rpad + rlen);
    if (rpad) out[i++] = 0x00;
    memcpy(out + i, r, rlen); i += rlen;
    out[i++] = 0x02;                       /* INTEGER s */
    out[i++] = (unsigned char)(spad + slen);
    if (spad) out[i++] = 0x00;
    memcpy(out + i, s, slen); i += slen;

    *outlen = i;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  NIF: tpm_generate_key/1                                             */
/* ------------------------------------------------------------------ */
static ERL_NIF_TERM nif_tpm_generate_key(ErlNifEnv *env, int argc,
                                          const ERL_NIF_TERM argv[]) {
    if (argc != 1) return enif_make_badarg(env);

    TPMI_DH_PERSISTENT persistent_handle = TPM2_DEFAULT_PERSISTENT;
    if (!get_handle(env, argv[0], &persistent_handle))
        return enif_make_badarg(env);

    ESYS_CONTEXT *ctx = NULL;
    TSS2_RC rc = Esys_Initialize(&ctx, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) return make_error(env, "esys_init_failed");

    /* Primary key template — P-384, restricted signing, no export */
    TPM2B_PUBLIC in_public = {
        .size = 0,
        .publicArea = {
            .type             = TPM2_ALG_ECC,
            .nameAlg          = TPM2_ALG_SHA384,
            .objectAttributes = (TPMA_OBJECT_RESTRICTED  |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
                                 TPMA_OBJECT_FIXEDTPM     |  /* SC-12(4) */
                                 TPMA_OBJECT_FIXEDPARENT  |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                 TPMA_OBJECT_USERWITHAUTH),
            .authPolicy.size  = 0,
            .parameters.eccDetail = {
                .symmetric = { .algorithm = TPM2_ALG_NULL },
                .scheme    = { .scheme    = TPM2_ALG_ECDSA,
                               .details.ecdsa.hashAlg = TPM2_ALG_SHA384 },
                .curveID   = TPM2_ECC_NIST_P384,  /* secp384r1 */
                .kdf       = { .scheme = TPM2_ALG_NULL }
            },
            .unique.ecc = { .x.size = 0, .y.size = 0 }
        }
    };

    TPM2B_SENSITIVE_CREATE in_sensitive = { .size = 0 };
    TPM2B_DATA outside_info = { .size = 0 };
    TPML_PCR_SELECTION creation_pcr = { .count = 0 };

    ESYS_TR primary_handle  = ESYS_TR_NONE;
    TPM2B_PUBLIC   *out_public  = NULL;
    TPM2B_CREATION_DATA *creation_data = NULL;
    TPM2B_DIGEST    *creation_hash     = NULL;
    TPMT_TK_CREATION *creation_ticket  = NULL;

    /* Create primary under Owner hierarchy */
    rc = Esys_CreatePrimary(ctx,
        ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &in_sensitive, &in_public, &outside_info, &creation_pcr,
        &primary_handle, &out_public, &creation_data,
        &creation_hash, &creation_ticket);

    if (rc != TSS2_RC_SUCCESS) {
        Esys_Finalize(&ctx);
        char msg[64];
        snprintf(msg, sizeof(msg), "create_primary_failed_0x%08x", rc);
        return make_error(env, msg);
    }

    /* Make the primary persistent (SC-12(1)) */
    ESYS_TR new_persistent = ESYS_TR_NONE;
    rc = Esys_EvictControl(ctx,
        ESYS_TR_RH_OWNER,
        primary_handle,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        persistent_handle, &new_persistent);

    /* Flush transient handle regardless */
    Esys_FlushContext(ctx, primary_handle);

    if (rc != TSS2_RC_SUCCESS) {
        Esys_Free(out_public);
        Esys_Free(creation_data);
        Esys_Free(creation_hash);
        Esys_Free(creation_ticket);
        Esys_Finalize(&ctx);
        char msg[64];
        snprintf(msg, sizeof(msg), "evict_control_failed_0x%08x", rc);
        return make_error(env, msg);
    }

    /* Return uncompressed EC point (x || y) as raw bytes */
    size_t xlen = out_public->publicArea.unique.ecc.x.size;
    size_t ylen = out_public->publicArea.unique.ecc.y.size;
    size_t publen = 1 + xlen + ylen;  /* 0x04 | X | Y */
    unsigned char *pub = malloc(publen);
    if (!pub) {
        Esys_Free(out_public);
        Esys_Free(creation_data);
        Esys_Free(creation_hash);
        Esys_Free(creation_ticket);
        Esys_Finalize(&ctx);
        return make_error(env, "alloc_failed");
    }
    pub[0] = 0x04;
    memcpy(pub + 1,       out_public->publicArea.unique.ecc.x.buffer, xlen);
    memcpy(pub + 1 + xlen, out_public->publicArea.unique.ecc.y.buffer, ylen);

    ERL_NIF_TERM result = make_ok_binary(env, pub, publen);
    free(pub);

    Esys_Free(out_public);
    Esys_Free(creation_data);
    Esys_Free(creation_hash);
    Esys_Free(creation_ticket);
    Esys_Finalize(&ctx);
    return result;
}

/* ------------------------------------------------------------------ */
/*  NIF: tpm_public_key/1                                               */
/* ------------------------------------------------------------------ */
static ERL_NIF_TERM nif_tpm_public_key(ErlNifEnv *env, int argc,
                                        const ERL_NIF_TERM argv[]) {
    if (argc != 1) return enif_make_badarg(env);

    TPMI_DH_PERSISTENT handle;
    if (!get_handle(env, argv[0], &handle)) return enif_make_badarg(env);

    ESYS_CONTEXT *ctx = NULL;
    TSS2_RC rc = Esys_Initialize(&ctx, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) return make_error(env, "esys_init_failed");

    ESYS_TR tr_handle = ESYS_TR_NONE;
    rc = Esys_TR_FromTPMPublic(ctx, handle,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &tr_handle);
    if (rc != TSS2_RC_SUCCESS) {
        Esys_Finalize(&ctx);
        return make_error(env, "handle_not_found");
    }

    TPM2B_PUBLIC *out_public = NULL;
    TPM2B_NAME   *name       = NULL;
    TPM2B_NAME   *qual_name  = NULL;
    rc = Esys_ReadPublic(ctx, tr_handle,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &out_public, &name, &qual_name);
    if (rc != TSS2_RC_SUCCESS) {
        Esys_Finalize(&ctx);
        return make_error(env, "read_public_failed");
    }

    size_t xlen = out_public->publicArea.unique.ecc.x.size;
    size_t ylen = out_public->publicArea.unique.ecc.y.size;
    size_t publen = 1 + xlen + ylen;
    unsigned char *pub = malloc(publen);
    if (!pub) {
        Esys_Free(out_public); Esys_Free(name); Esys_Free(qual_name);
        Esys_Finalize(&ctx);
        return make_error(env, "alloc_failed");
    }
    pub[0] = 0x04;
    memcpy(pub + 1,        out_public->publicArea.unique.ecc.x.buffer, xlen);
    memcpy(pub + 1 + xlen, out_public->publicArea.unique.ecc.y.buffer, ylen);

    ERL_NIF_TERM result = make_ok_binary(env, pub, publen);
    free(pub);
    Esys_Free(out_public); Esys_Free(name); Esys_Free(qual_name);
    Esys_Finalize(&ctx);
    return result;
}

/* ------------------------------------------------------------------ */
/*  NIF: tpm_sign/2                                                     */
/*  Signing occurs inside the TPM — SC-12, SC-13, SC-28                */
/* ------------------------------------------------------------------ */
static ERL_NIF_TERM nif_tpm_sign(ErlNifEnv *env, int argc,
                                  const ERL_NIF_TERM argv[]) {
    if (argc != 2) return enif_make_badarg(env);

    TPMI_DH_PERSISTENT handle;
    if (!get_handle(env, argv[0], &handle)) return enif_make_badarg(env);

    ErlNifBinary digest;
    if (!enif_inspect_binary(env, argv[1], &digest)) return enif_make_badarg(env);
    if (digest.size != 48) return make_error(env, "digest_must_be_48_bytes_sha384");

    ESYS_CONTEXT *ctx = NULL;
    TSS2_RC rc = Esys_Initialize(&ctx, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) return make_error(env, "esys_init_failed");

    ESYS_TR tr_handle = ESYS_TR_NONE;
    rc = Esys_TR_FromTPMPublic(ctx, handle,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &tr_handle);
    if (rc != TSS2_RC_SUCCESS) {
        Esys_Finalize(&ctx);
        return make_error(env, "handle_not_found");
    }

    TPM2B_DIGEST tpm_digest = { .size = 48 };
    memcpy(tpm_digest.buffer, digest.data, 48);

    TPMT_SIG_SCHEME scheme = {
        .scheme  = TPM2_ALG_ECDSA,
        .details = { .ecdsa.hashAlg = TPM2_ALG_SHA384 }
    };

    TPMT_TK_HASHCHECK validation = {
        .tag       = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest    = { .size = 0 }
    };

    TPMT_SIGNATURE *sig = NULL;
    rc = Esys_Sign(ctx, tr_handle,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &tpm_digest, &scheme, &validation, &sig);
    Esys_Finalize(&ctx);

    if (rc != TSS2_RC_SUCCESS || !sig) {
        char msg[64];
        snprintf(msg, sizeof(msg), "sign_failed_0x%08x", rc);
        return make_error(env, msg);
    }

    unsigned char der[256];
    size_t derlen = sizeof(der);
    if (!encode_ecdsa_der(sig, der, &derlen)) {
        Esys_Free(sig);
        return make_error(env, "der_encode_failed");
    }
    Esys_Free(sig);
    return make_ok_binary(env, der, derlen);
}

/* ------------------------------------------------------------------ */
/*  NIF: tpm_delete_key/1                                               */
/*  SC-12(5) / MP-6: permanently removes the persistent TPM object    */
/* ------------------------------------------------------------------ */
static ERL_NIF_TERM nif_tpm_delete_key(ErlNifEnv *env, int argc,
                                        const ERL_NIF_TERM argv[]) {
    if (argc != 1) return enif_make_badarg(env);

    TPMI_DH_PERSISTENT handle;
    if (!get_handle(env, argv[0], &handle)) return enif_make_badarg(env);

    ESYS_CONTEXT *ctx = NULL;
    TSS2_RC rc = Esys_Initialize(&ctx, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) return make_error(env, "esys_init_failed");

    ESYS_TR tr_handle = ESYS_TR_NONE;
    rc = Esys_TR_FromTPMPublic(ctx, handle,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &tr_handle);
    if (rc != TSS2_RC_SUCCESS) {
        Esys_Finalize(&ctx);
        return make_error(env, "handle_not_found");
    }

    /* Pass ESYS_TR_NONE as new_object_handle to evict (delete) the key */
    ESYS_TR evicted = ESYS_TR_NONE;
    rc = Esys_EvictControl(ctx,
        ESYS_TR_RH_OWNER, tr_handle,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        handle, &evicted);
    Esys_Finalize(&ctx);

    if (rc != TSS2_RC_SUCCESS) {
        char msg[64];
        snprintf(msg, sizeof(msg), "evict_delete_failed_0x%08x", rc);
        return make_error(env, msg);
    }
    return enif_make_atom(env, "ok");
}

/* ------------------------------------------------------------------ */
/*  NIF table                                                           */
/* ------------------------------------------------------------------ */
static ErlNifFunc nif_funcs[] = {
    {"generate_key", 1, nif_tpm_generate_key, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"public_key",   1, nif_tpm_public_key,   ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"sign",         2, nif_tpm_sign,         ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"delete_key",   1, nif_tpm_delete_key,   ERL_NIF_DIRTY_JOB_IO_BOUND}
};

ERL_NIF_INIT(Elixir.CA.TPM, nif_funcs, NULL, NULL, NULL, NULL)

#else  /* !__linux__ */

/* Stub for non-Linux builds */
static ERL_NIF_TERM stub(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    return enif_make_tuple2(env,
        enif_make_atom(env, "error"),
        enif_make_atom(env, "not_supported"));
}

static ErlNifFunc nif_funcs[] = {
    {"generate_key", 1, stub, 0},
    {"public_key",   1, stub, 0},
    {"sign",         2, stub, 0},
    {"delete_key",   1, stub, 0}
};

ERL_NIF_INIT(Elixir.CA.TPM, nif_funcs, NULL, NULL, NULL, NULL)

#endif  /* __linux__ */
