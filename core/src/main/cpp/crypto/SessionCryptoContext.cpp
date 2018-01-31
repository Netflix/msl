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

#include <crypto/SessionCryptoContext.h>
#include <MslError.h>
#include <MslMasterTokenException.h>
#include <tokens/MasterToken.h>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace crypto {

namespace {

string toString(int64_t number)
{
    stringstream ss;
    ss << number;
    return ss.str();
}
} // namespace anonymous

SessionCryptoContext::SessionCryptoContext(shared_ptr<util::MslContext> ctx, shared_ptr<MasterToken> masterToken)
: SymmetricCryptoContext(
        ctx,
        masterToken->getIdentity().empty() ? toString(masterToken->getSequenceNumber()) : masterToken->getIdentity() + "_" + toString(masterToken->getSequenceNumber()),
        masterToken->getEncryptionKey(),
        masterToken->getSignatureKey(),
        SecretKey())
{
    if (!masterToken->isDecrypted())
        throw MslMasterTokenException(MslError::MASTERTOKEN_UNTRUSTED, masterToken);
}


SessionCryptoContext::SessionCryptoContext(shared_ptr<MslContext> ctx, shared_ptr<tokens::MasterToken> masterToken,
        const string& identity, const SecretKey& encryptionKey, const SecretKey& hmacKey)
: SymmetricCryptoContext(
        ctx,
        identity.empty() ? toString(masterToken->getSequenceNumber()) : identity + "_" + toString(masterToken->getSequenceNumber()),
        encryptionKey,
        hmacKey,
        SecretKey())
{
}


}}} // namespace netflix::msl::crypto

