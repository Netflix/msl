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
#include <MslCryptoException.h>
#include "util.h"
#include <MslInternalException.h>
#include <openssl/evp.h>
#include <util/ScopedDisposer.h>

namespace netflix {
namespace msl {
namespace crypto {

/**
* Safely compares two byte arrays in a way immune to timing attacks.
*
* @param s1 first array for the comparison.
* @param s2 second array for the comparison.
* @param n size of n1, should be equal also to size of n2
* @return true if the arrays are equal up to n1, false if they are not.
*/
bool safeMemEqual(const void* s1, const void* s2, size_t n1) {
    const unsigned char* s1_ptr = reinterpret_cast<const unsigned char*>(s1);
    const unsigned char* s2_ptr = reinterpret_cast<const unsigned char*>(s2);
    unsigned char tmp = 0;
    for (size_t i = 0; i < n1; ++i, ++s1_ptr, ++s2_ptr)
        tmp |= *s1_ptr ^ *s2_ptr;
    return (tmp == 0);
}

const EVP_MD * evp_md(const std::string& algName)
{
    if (algName == "SHA224")
        return EVP_sha224();
    else if (algName == "SHA256")
        return EVP_sha256();
    else if (algName == "SHA384")
        return EVP_sha384();
    else if (algName == "SHA512")
        return EVP_sha512();
    else
        throw MslInternalException("Digest algorithm " + algName + " not found.");
}

}}} // namespace netflix::msl::crypto

