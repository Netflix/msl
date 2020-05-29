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

#include <crypto/OpenSslLib.h>
#include <crypto/opensslImpl/util.h>
#include <MslInternalException.h>
#include <numerics/safe_math.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <util/ScopedDisposer.h>

using namespace std;
using namespace netflix::msl::util;

using base::internal::CheckedNumeric;

namespace netflix {
namespace msl {
namespace crypto {

void digest(const string& spec, const ByteArray& data, ByteArray& md)
{
    OpenSslErrStackTracer errTracer;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ScopedDisposer<EVP_MD_CTX, void, EVP_MD_CTX_destroy> evpMd(EVP_MD_CTX_create());
#else
    ScopedDisposer<EVP_MD_CTX, void, EVP_MD_CTX_free> evpMd(EVP_MD_CTX_new());
#endif
    if (!evpMd.get())
        throw MslInternalException("digest: EVP_MD_CTX_create unable to create EVP_MD_CTX");

    if (EVP_DigestInit_ex(evpMd.get(), evp_md(spec), NULL) != 1)
        throw MslInternalException("digest: EVP_DigestInit_ex error");

    CheckedNumeric<size_t> dataSize(data.size());
    if (EVP_DigestUpdate(evpMd.get(), &data[0], CheckedNumeric<size_t>::cast(dataSize).ValueOrDie()) != 1)
        throw MslInternalException("digest: EVP_DigestUpdate error");

    ByteArray tmp(EVP_MAX_MD_SIZE);
    unsigned int outLen = 0;
    if (EVP_DigestFinal_ex(evpMd.get(), &tmp[0], &outLen) != 1)
        throw MslInternalException("digest: EVP_DigestFinal_ex error");

    ByteArray(tmp.begin(), tmp.begin()+outLen).swap(md);
}

}}} // namespace netflix::msl::crypto
