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

#ifndef SRC_CRYPTO_OPENSSLIMPL_UTIL_H_
#define SRC_CRYPTO_OPENSSLIMPL_UTIL_H_

#include <openssl/evp.h>
#include <stddef.h>
#include <string>
#include <memory>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace crypto {

bool safeMemEqual(const void* s1, const void* s2, size_t n1);

const EVP_MD * evp_md(const std::string& algName);

}}} // namespace netflix::msl::crypto

#endif /* SRC_CRYPTO_OPENSSLIMPL_UTIL_H_ */