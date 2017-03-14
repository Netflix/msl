/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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

#include "../OpenSslLib.h"
#include <MslInternalException.h>
#include <numerics/safe_math.h>
#include <openssl/x509.h>
#include <util/ScopedDisposer.h>

using base::internal::CheckedNumeric;

using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace crypto {

namespace {
typedef ScopedDisposer<BIGNUM, void, BN_free> BigNum;
}

// FIXME: Change this code to use OpenSSL's EVP interface
// https://wiki.openssl.org/index.php/EVP_Key_Agreement

void dhGenKeyPair(const ByteArray& p, const ByteArray& g, ByteArray& pubKey, ByteArray& privKey)
{
    OpenSslErrStackTracer errTracer;

    ScopedDisposer<DH, void, DH_free> dh(DH_new());
    if (!dh.get())
        throw MslInternalException("dhGenKeyPair: DH_new() unable to create DH struct");

    // DH_new creates a DH struct with p & g set to NULL; convert and copy in our new values
    CheckedNumeric<size_t> pSize(p.size());
    BigNum pbn(BN_bin2bn(&p[0], CheckedNumeric<int>::cast(pSize).ValueOrDie(), NULL));
    if (!pbn.get())
        throw MslInternalException("dhGenKeyPair: BN_bin2bn() error making bignum from p");
    CheckedNumeric<size_t> gSize(g.size());
    BigNum gbn(BN_bin2bn(&g[0], CheckedNumeric<int>::cast(gSize).ValueOrDie(), NULL));
    if (!gbn.get())
        throw MslInternalException("dhGenKeyPair: BN_bin2bn() error making bignum g");
    if (!(dh.get()->p = BN_dup(pbn.get())))
        throw MslInternalException("dhGenKeyPair: BN_dup() unable to duplicate DH prime");
    if (!(dh.get()->g = BN_dup(gbn.get())))
        throw MslInternalException("dhGenKeyPair: BN_dup() unable to duplicate DH generator");

    // Generate the public/private key pair
    if (!DH_generate_key(dh.get()))
        throw MslInternalException("dhGenKeyPair: DH_generate_key() unable to generate key pair");

    const BIGNUM * const pubBn = dh.get()->pub_key;
    const int pubSizeBytes = BN_num_bytes(pubBn);
    ByteArray pubBuf(static_cast<const size_t>(pubSizeBytes), 0);
    int sizeResult = BN_bn2bin(pubBn, &pubBuf[0]); (void) sizeResult;
    if (sizeResult != pubSizeBytes)
        throw MslInternalException("dhGenKeyPair: BN_bn2bin() error converting public key");

    const BIGNUM * const privBn = dh.get()->priv_key;
    const int privSizeBytes = BN_num_bytes(privBn);
    ByteArray privBuf(static_cast<const size_t>(privSizeBytes), 0);
    sizeResult = BN_bn2bin(privBn, &privBuf[0]); (void) sizeResult;
    if (sizeResult != privSizeBytes)
        throw MslInternalException("dhGenKeyPair: BN_bn2bin() error converting private key");

    pubKey.swap(pubBuf);
    privKey.swap(privBuf);
}

void dhComputeSharedSecret(const ByteArray& remotePublicKey, const ByteArray& p,
        const ByteArray& localPrivateKey, ByteArray& sharedSecret)
{
    OpenSslErrStackTracer errTracer;

    if (remotePublicKey.empty())
        throw MslInternalException("computeSharedSecret: Empty public key");
    if (localPrivateKey.empty())
        throw MslInternalException("computeSharedSecret: Empty private key");

    ScopedDisposer<DH, void, DH_free> dh(DH_new());
    if (!dh.get())
        throw MslInternalException("computeSharedSecret: DH_new() unable to create DH struct");

    // DH_new creates an empty DH struct, copy in p and localPrivateKey
    CheckedNumeric<size_t> pSize(p.size());
    BigNum pbn(BN_bin2bn(&p[0], CheckedNumeric<int>::cast(pSize).ValueOrDie(), NULL));
    if (!pbn.get())
        throw MslInternalException("computeSharedSecret: BN_bin2bn() error making bignum from p");
    if (!(dh.get()->p = BN_dup(pbn.get())))
        throw MslInternalException("computeSharedSecret: BN_dup() unable to duplicate DH prime");
    CheckedNumeric<size_t> localPrivateKeySize(localPrivateKey.size());
    BigNum localPrivateKeyBn(BN_bin2bn(&localPrivateKey[0], CheckedNumeric<int>::cast(localPrivateKeySize).ValueOrDie(), NULL));
    if (!localPrivateKeyBn.get())
        throw MslInternalException("computeSharedSecret: BN_bin2bn() error making bignum from private key");
    if (!(dh.get()->priv_key = BN_dup(localPrivateKeyBn.get())))
        throw MslInternalException("computeSharedSecret: BN_dup() unable to duplicate DH private key");

    // make remotePublicKey into a BIGNUM
    CheckedNumeric<size_t> remotePublicKeySize(remotePublicKey.size());
    BigNum remotePublicKeyBn(BN_bin2bn(&remotePublicKey[0], CheckedNumeric<int>::cast(remotePublicKeySize).ValueOrDie(), NULL));

    // get size needed for shared secret
    int outLen = DH_size(dh.get());
    // allocate and zero space for the shared secret
    ByteArray tmp = ByteArray(static_cast<size_t>(outLen), 0);

    // compute the shared secret
    outLen = DH_compute_key(&tmp[0], remotePublicKeyBn.get(), dh.get());
    if (outLen < 0)
        throw MslInternalException("computeSharedSecret: DH_compute_key() error");

    ByteArray(tmp.begin(), tmp.begin()+outLen).swap(sharedSecret);
}

}}} // namespace netflix::msl:;crypto
