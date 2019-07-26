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

#ifndef SRC_CRYPTO_JCAALGORITHM_H_
#define SRC_CRYPTO_JCAALGORITHM_H_

#include <string>

namespace netflix {
namespace msl {
namespace crypto {

namespace JcaAlgorithm {

static const std::string AES = "AES";
/** HMAC-SHA256. */
static const std::string HMAC_SHA256 = "HmacSHA256";
/** AES key wrap. */
static const std::string AESKW = "AES";
/** CMAC. */
static const std::string AES_CMAC = "AESCmac";
/** SHA256 w/RSA. */
static const std::string SHA256withRSA = "SHA256withRSA";
/** ECDSA. */
static const std::string ECDSA = "ECDSA";

}}}} // namespace netflix::msl::crypto::JcaAlgorithm

#endif /* SRC_CRYPTO_JCAALGORITHM_H_ */
