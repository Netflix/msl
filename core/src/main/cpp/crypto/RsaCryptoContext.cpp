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

#include <crypto/RsaCryptoContext.h>
#include <crypto/Key.h>
#include <MslInternalException.h>
#include <util/MslContext.h>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::crypto;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace crypto {

RsaCryptoContext::RsaCryptoContext(shared_ptr<MslContext>, const string& id,
        const PrivateKey& privateKey, const PublicKey& publicKey, const Mode& algo)
    : AsymmetricCryptoContext(
            id,
            privateKey,
            publicKey,
            (algo == Mode::ENCRYPT_DECRYPT_PKCS1) ? "RSA/ECB/PKCS1Padding" : (algo == Mode::ENCRYPT_DECRYPT_OAEP) ? "RSA/ECB/OAEPPadding" : NULL_OP,
            (algo == Mode::SIGN_VERIFY) ? "SHA256withRSA" : NULL_OP
      )
{
    if (algo == Mode::WRAP_UNWRAP)
        throw MslInternalException("Wrap/unwrap unsupported.");
}

}}} // namespace netflic::msl::crypto
