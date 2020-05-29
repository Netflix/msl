/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Portions Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the Chromium LICENSE file.

#include <assert.h>
#include <crypto/OpenSslLib.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>

#include <MslCryptoException.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <openssl/evp.h>

#include <openssl/x509.h>
#include <openssl/opensslv.h>
#include <stdint.h>
#include <util/ScopedDisposer.h>
#include <vector>

using namespace netflix::msl::util;

using std::vector;

namespace netflix {
namespace msl {
typedef vector<uint8_t> ByteArray;
namespace crypto {

namespace {

typedef int (*InitFunc)(EVP_PKEY_CTX* ctx);
typedef int (*EncryptDecryptFunc)(EVP_PKEY_CTX* ctx, unsigned char* out,
        size_t* outlen, const unsigned char* in, size_t inlen);

// Helper for doing either RSA-OAEP encryption or decryption.
//
// To encrypt call with:
//   init_func=EVP_PKEY_encrypt_init, encrypt_decrypt_func=EVP_PKEY_encrypt
//
// To decrypt call with:
//   init_func=EVP_PKEY_decrypt_init, encrypt_decrypt_func=EVP_PKEY_decrypt
//
// Note: this function takes ownership of the input EVP_PKEY and frees it on
// exit.
void encryptDecrypt(InitFunc init_func, EncryptDecryptFunc encrypt_decrypt_func,
        bool useOaepPadding, EVP_PKEY* pkey, const ByteArray& data, ByteArray& out)
{
    OpenSslErrStackTracer errTracer;

    assert(init_func);
    assert(encrypt_decrypt_func);

    const bool isEncrypt = (init_func == EVP_PKEY_encrypt_init);

    // Verify the type of the EVP_KEY.
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA)
        throw MslCryptoException(isEncrypt ? MslError::INVALID_PUBLIC_KEY : MslError::INVALID_PRIVATE_KEY, "");

    // Create and init an EVP_PKEY_CTX for the encryption operation
    ScopedDisposer<EVP_PKEY_CTX, void, EVP_PKEY_CTX_free> ctx(EVP_PKEY_CTX_new(pkey, NULL));
    if (ctx.isEmpty())
        throw MslInternalException("EVP_PKEY_CTX_new failed.");
    if (init_func(ctx.get()) != 1)
        throw MslInternalException("EVP_PKEY_encrypt/decrypt_init failed.");

    // Set padding
    if (useOaepPadding) {
        // note we are not setting the optional 'label' for OAEP padding
        if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha1()) <= 0 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha1()) <= 0)
            throw MslInternalException("Error when configuring RSA_PKCS1_OAEP_PADDING");
    } else {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) <= 0)
            throw MslInternalException("Error when configuring RSA_PKCS1_PADDING");
    }

    // Determine the maximum length of the output.
    size_t outlen = 0;
    if (encrypt_decrypt_func(ctx.get(), NULL, &outlen, &data[0], data.size()) != 1) {
        throw MslCryptoException(isEncrypt ? MslError::ENCRYPT_ERROR : MslError::DECRYPT_ERROR);
    }
    ByteArray result(outlen);

    // Do the actual encryption/decryption.
    if (encrypt_decrypt_func(ctx.get(), &result[0], &outlen, &data[0], data.size()) != 1) {
        throw MslCryptoException(isEncrypt ? MslError::ENCRYPT_ERROR : MslError::DECRYPT_ERROR);
    }
    result.resize(outlen);
    out.swap(result);
}

void sign(EVP_PKEY* pkey, const ByteArray& data, ByteArray& signature)
{
    OpenSslErrStackTracer errTracer;

    // Verify the type of the EVP_KEY.
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA)
        throw MslCryptoException(MslError::INVALID_PRIVATE_KEY);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ScopedDisposer<EVP_MD_CTX, void, EVP_MD_CTX_destroy> ctx(EVP_MD_CTX_create());
#else
    ScopedDisposer<EVP_MD_CTX, void, EVP_MD_CTX_free> ctx(EVP_MD_CTX_new());
#endif
    if (ctx.isEmpty())
        throw MslInternalException("EVP_MD_CTX_new failed.");
    EVP_PKEY_CTX* pctx = NULL;  // Owned by |ctx|.

    // NOTE: A call to EVP_DigestSignFinal() with a NULL second parameter
    // returns a maximum allocation size, while the call without a NULL returns
    // the real one, which may be smaller.
    size_t sigLen = 0;
    if (EVP_DigestSignInit(ctx.get(), &pctx, EVP_sha256(), NULL, pkey) != 1)
        throw MslInternalException("EVP_DigestSignInit failed.");

    if (EVP_DigestSignUpdate(ctx.get(), &data[0], data.size()) != 1 ||
        EVP_DigestSignFinal(ctx.get(), NULL, &sigLen) != 1) {
        throw MslCryptoException(MslError::SIGNATURE_ERROR);
    }

    ByteArray result(sigLen);
    if (EVP_DigestSignFinal(ctx.get(), &result[0], &sigLen) != 1)
        throw MslCryptoException(MslError::SIGNATURE_ERROR);

    result.resize(sigLen);
    signature.swap(result);
}

bool verify(EVP_PKEY* pkey, const ByteArray& data, const ByteArray& signature)
{
    OpenSslErrStackTracer errTracer;

    // Verify the type of the EVP_KEY.
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA)
        throw MslCryptoException(MslError::INVALID_PUBLIC_KEY);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ScopedDisposer<EVP_MD_CTX, void, EVP_MD_CTX_destroy> ctx(EVP_MD_CTX_create());
#else
    ScopedDisposer<EVP_MD_CTX, void, EVP_MD_CTX_free> ctx(EVP_MD_CTX_new());
#endif
    if (ctx.isEmpty())
        throw MslInternalException("EVP_MD_CTX_new failed.");
    EVP_PKEY_CTX* pctx = NULL;  // Owned by |ctx|.

    if (EVP_DigestVerifyInit(ctx.get(), &pctx, EVP_sha256(), NULL, pkey) != 1)
        throw MslInternalException("EVP_DigestVerifyInit failed.");

    if (EVP_DigestVerifyUpdate(ctx.get(), &data[0], data.size()) != 1)
        throw MslCryptoException(MslError::SIGNATURE_ERROR);

    return (1 == EVP_DigestVerifyFinal(ctx.get(), &signature[0], signature.size()));
}

} // namespace anonymous

void rsaEncrypt(EVP_PKEY* pkey, const ByteArray& plaintext, bool isOaepPadding, ByteArray& ciphertext)
{
    assert(pkey);
    encryptDecrypt(EVP_PKEY_encrypt_init, EVP_PKEY_encrypt, isOaepPadding, pkey, plaintext, ciphertext);
}

void rsaDecrypt(EVP_PKEY* pkey, const ByteArray& ciphertext, bool isOaepPadding, ByteArray& plaintext)
{
    assert(pkey);
    encryptDecrypt(EVP_PKEY_decrypt_init, EVP_PKEY_decrypt, isOaepPadding, pkey, ciphertext, plaintext);
}

void rsaSign(EVP_PKEY* pkey, const ByteArray& data, ByteArray& signature)
{
    assert(pkey);
    sign(pkey, data, signature);
}

bool rsaVerify(EVP_PKEY* pkey, const ByteArray& data, const ByteArray& signature)
{
    assert(pkey);
    return verify(pkey, data, signature);
}

}}} // namespace netflix::msl::crypto
