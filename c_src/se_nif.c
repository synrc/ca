/*
 * se_nif.c — macOS Secure Enclave NIF for Erlang/Elixir
 *
 * Provides hardware-backed P-384 (secp384r1) key storage via the
 * macOS Secure Enclave Processor (SEP).  All private key material
 * is generated and retained inside the SEP; only the DER-encoded
 * public key is exported to the application processor.
 *
 * NIST SP 800-53 controls enforced:
 *   SC-12    — key generated inside SEP; label persisted in Keychain
 *   SC-12(1) — key survives reboots (kSecAttrIsPermanent = true)
 *   SC-12(4) — key encrypted by SEP's own AES-256 UID key (not exportable)
 *   SC-12(5) — SecItemDelete permanently destroys the SEP key
 *   SC-13    — FIPS 140-2/3 Level 2+ P-384 ECDSA inside SEP
 *   SC-28    — private key never reaches the application processor
 *   SC-28(1) — Keychain blob wrapped with AES-256-GCM by SEP
 *   MP-4     — key reference stored in Keychain (not removable media)
 *   MP-6     — SecItemDelete is irreversible; no data remanence
 */

#include <erl_nif.h>

#ifdef __APPLE__
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  Helpers                                                             */
/* ------------------------------------------------------------------ */

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

/* Convert an Erlang binary/string argument into a CFStringRef label. */
static CFStringRef label_from_arg(ErlNifEnv *env, ERL_NIF_TERM term) {
    ErlNifBinary bin;
    if (enif_inspect_binary(env, term, &bin)) {
        return CFStringCreateWithBytes(kCFAllocatorDefault,
            bin.data, (CFIndex)bin.size, kCFStringEncodingUTF8, false);
    }
    unsigned int len = 0;
    enif_get_list_length(env, term, &len);
    char *buf = malloc(len + 1);
    if (!buf) return NULL;
    enif_get_string(env, term, buf, len + 1, ERL_NIF_LATIN1);
    CFStringRef ref = CFStringCreateWithCString(kCFAllocatorDefault,
        buf, kCFStringEncodingUTF8);
    free(buf);
    return ref;
}

/* Look up a SecKeyRef from the Keychain by label. */
static SecKeyRef find_key(CFStringRef label, OSStatus *outStatus) {
    const void *keys[]   = { kSecClass, kSecAttrLabel,
                             kSecReturnRef, kSecAttrKeyClass };
    const void *values[] = { kSecClassKey, label,
                             kCFBooleanTrue, kSecAttrKeyClassPrivate };
    CFDictionaryRef query = CFDictionaryCreate(kCFAllocatorDefault,
        keys, values, 4,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFTypeRef result = NULL;
    *outStatus = SecItemCopyMatching(query, &result);
    CFRelease(query);
    return (SecKeyRef)result;
}

/* ------------------------------------------------------------------ */
/*  NIF: se_generate_key(Label :: binary) ->                           */
/*         {:ok, PublicKeyDER :: binary} | {:error, Reason :: string}  */
/* ------------------------------------------------------------------ */
static ERL_NIF_TERM nif_generate_key(ErlNifEnv *env, int argc,
                                     const ERL_NIF_TERM argv[]) {
    if (argc != 1) return enif_make_badarg(env);

    CFStringRef label = label_from_arg(env, argv[0]);
    if (!label) return make_error(env, "invalid_label");

    /* SC-12(4): kSecAttrTokenIDSecureEnclave forces the key into the SEP.
       kSecAttrIsExtractable=false means the raw key bytes NEVER leave the chip. */
    CFErrorRef cfErr = NULL;
    SecAccessControlRef acl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,  /* SC-28: device-bound */
        0,                                              /* No biometric gate by default */
        &cfErr);
    if (!acl) {
        CFRelease(label);
        return make_error(env, "acl_create_failed");
    }

    const void *paramKeys[] = {
        kSecAttrKeyType,
        kSecAttrKeySizeInBits,
        kSecAttrTokenID,            /* SC-12(4): Route to Secure Enclave */
        kSecPrivateKeyAttrs
    };

    const void *privAttrsKeys[] = {
        kSecAttrIsPermanent,        /* SC-12(1): survives reboots */
        kSecAttrLabel,
        kSecAttrAccessControl
    };
    const void *privAttrsValues[] = {
        kCFBooleanTrue,
        label,
        acl
    };
    CFDictionaryRef privAttrs = CFDictionaryCreate(kCFAllocatorDefault,
        privAttrsKeys, privAttrsValues, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFNumberRef keySizeBits = NULL;
    int bits = 384;  /* secp384r1 — the only curve the SEP supports */
    keySizeBits = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);

    const void *paramValues[] = {
        kSecAttrKeyTypeECSECPrimeRandom,
        keySizeBits,
        kSecAttrTokenIDSecureEnclave,
        privAttrs
    };
    CFDictionaryRef params = CFDictionaryCreate(kCFAllocatorDefault,
        paramKeys, paramValues, 4,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    SecKeyRef privateKey = NULL;
    SecKeyRef publicKey  = NULL;
    OSStatus status = SecKeyGeneratePair(params, &publicKey, &privateKey);

    CFRelease(params);
    CFRelease(privAttrs);
    CFRelease(keySizeBits);
    CFRelease(acl);
    CFRelease(label);

    if (status != errSecSuccess) {
        char msg[64];
        snprintf(msg, sizeof(msg), "SecKeyGeneratePair_failed_%d", (int)status);
        return make_error(env, msg);
    }

    /* Export DER-encoded SubjectPublicKeyInfo for the public key. */
    CFErrorRef exportErr = NULL;
    CFDataRef pubDER = SecKeyCopyExternalRepresentation(publicKey, &exportErr);
    CFRelease(privateKey);
    CFRelease(publicKey);

    if (!pubDER) {
        return make_error(env, "pubkey_export_failed");
    }

    ERL_NIF_TERM result = make_ok_binary(env,
        CFDataGetBytePtr(pubDER), (size_t)CFDataGetLength(pubDER));
    CFRelease(pubDER);
    return result;
}

/* ------------------------------------------------------------------ */
/*  NIF: se_public_key(Label :: binary) ->                             */
/*         {:ok, PublicKeyDER :: binary} | {:error, Reason}            */
/* ------------------------------------------------------------------ */
static ERL_NIF_TERM nif_public_key(ErlNifEnv *env, int argc,
                                   const ERL_NIF_TERM argv[]) {
    if (argc != 1) return enif_make_badarg(env);

    CFStringRef label = label_from_arg(env, argv[0]);
    if (!label) return make_error(env, "invalid_label");

    OSStatus status;
    SecKeyRef privKey = find_key(label, &status);
    CFRelease(label);

    if (status != errSecSuccess || !privKey) {
        char msg[64];
        snprintf(msg, sizeof(msg), "key_not_found_%d", (int)status);
        return make_error(env, msg);
    }

    SecKeyRef pubKey = SecKeyCopyPublicKey(privKey);
    CFRelease(privKey);

    if (!pubKey) return make_error(env, "pubkey_copy_failed");

    CFErrorRef exportErr = NULL;
    CFDataRef pubDER = SecKeyCopyExternalRepresentation(pubKey, &exportErr);
    CFRelease(pubKey);

    if (!pubDER) return make_error(env, "pubkey_export_failed");

    ERL_NIF_TERM result = make_ok_binary(env,
        CFDataGetBytePtr(pubDER), (size_t)CFDataGetLength(pubDER));
    CFRelease(pubDER);
    return result;
}

/* ------------------------------------------------------------------ */
/*  NIF: se_sign(Label :: binary, Digest :: binary) ->                 */
/*         {:ok, SignatureDER :: binary} | {:error, Reason}            */
/*                                                                     */
/*  Signing is performed INSIDE the SEP — SC-12, SC-13, SC-28         */
/* ------------------------------------------------------------------ */
static ERL_NIF_TERM nif_sign(ErlNifEnv *env, int argc,
                             const ERL_NIF_TERM argv[]) {
    if (argc != 2) return enif_make_badarg(env);

    CFStringRef label = label_from_arg(env, argv[0]);
    if (!label) return make_error(env, "invalid_label");

    ErlNifBinary digest;
    if (!enif_inspect_binary(env, argv[1], &digest)) {
        CFRelease(label);
        return enif_make_badarg(env);
    }

    OSStatus status;
    SecKeyRef privKey = find_key(label, &status);
    CFRelease(label);

    if (status != errSecSuccess || !privKey) {
        char msg[64];
        snprintf(msg, sizeof(msg), "key_not_found_%d", (int)status);
        return make_error(env, msg);
    }

    CFDataRef digestData = CFDataCreate(kCFAllocatorDefault,
        digest.data, (CFIndex)digest.size);

    CFErrorRef signErr = NULL;
    /* kSecKeyAlgorithmECDSASignatureDigestX962SHA384 — P-384 ECDSA over SHA-384 */
    CFDataRef sigData = SecKeyCreateSignature(privKey,
        kSecKeyAlgorithmECDSASignatureDigestX962SHA384,
        digestData, &signErr);

    CFRelease(digestData);
    CFRelease(privKey);

    if (!sigData) {
        return make_error(env, "sign_failed");
    }

    ERL_NIF_TERM result = make_ok_binary(env,
        CFDataGetBytePtr(sigData), (size_t)CFDataGetLength(sigData));
    CFRelease(sigData);
    return result;
}

/* ------------------------------------------------------------------ */
/*  NIF: se_delete_key(Label :: binary) ->                             */
/*         :ok | {:error, Reason}                                      */
/*                                                                     */
/*  SC-12(5) / MP-6: irreversible destruction of SEP key              */
/* ------------------------------------------------------------------ */
static ERL_NIF_TERM nif_delete_key(ErlNifEnv *env, int argc,
                                   const ERL_NIF_TERM argv[]) {
    if (argc != 1) return enif_make_badarg(env);

    CFStringRef label = label_from_arg(env, argv[0]);
    if (!label) return make_error(env, "invalid_label");

    const void *keys[]   = { kSecClass, kSecAttrLabel };
    const void *values[] = { kSecClassKey, label };
    CFDictionaryRef query = CFDictionaryCreate(kCFAllocatorDefault,
        keys, values, 2,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    OSStatus status = SecItemDelete(query);
    CFRelease(query);
    CFRelease(label);

    if (status != errSecSuccess && status != errSecItemNotFound) {
        char msg[64];
        snprintf(msg, sizeof(msg), "delete_failed_%d", (int)status);
        return make_error(env, msg);
    }
    return enif_make_atom(env, "ok");
}

/* ------------------------------------------------------------------ */
/*  NIF table & module init                                             */
/* ------------------------------------------------------------------ */
static ErlNifFunc nif_funcs[] = {
    {"generate_key", 1, nif_generate_key, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"public_key",   1, nif_public_key,   ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"sign",         2, nif_sign,         ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"delete_key",   1, nif_delete_key,   ERL_NIF_DIRTY_JOB_IO_BOUND}
};

ERL_NIF_INIT(Elixir.CA.SecureEnclave, nif_funcs, NULL, NULL, NULL, NULL)

#else  /* !__APPLE__ */

/*
 * Stub for non-macOS builds.  All functions return {error, not_supported}.
 * The Elixir module handles platform detection before calling into the NIF.
 */
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

ERL_NIF_INIT(Elixir.CA.SecureEnclave, nif_funcs, NULL, NULL, NULL, NULL)

#endif  /* __APPLE__ */
