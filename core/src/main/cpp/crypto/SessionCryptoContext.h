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

#ifndef SRC_CRYPTO_SESSIONCRYPTOCONTEXT_H_
#define SRC_CRYPTO_SESSIONCRYPTOCONTEXT_H_

#include <crypto/SymmetricCryptoContext.h>
#include <Macros.h>

namespace netflix {
namespace msl {
namespace tokens { class MasterToken; }
namespace util { class MslContext; }
namespace crypto {

/**
 * This is a convenience class for constructing a symmetric crypto context from
 * a MSL session master token.
 */
class SessionCryptoContext: public SymmetricCryptoContext
{
public:
    virtual ~SessionCryptoContext() {}

    /**
     * <p>Construct a new session crypto context from the provided master
     * token.</p>
     *
     * @param ctx MSL context.
     * @param masterToken the master token.
     * @throws MslMasterTokenException if the master token is not trusted.
     */
    SessionCryptoContext(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<tokens::MasterToken> masterToken);

    /**
     * <p>Construct a new session crypto context from the provided master token.
     * The entity identity and keys are assumed to be the same as what is
     * inside the master token, which may be untrusted.</p>
     *
     * @param ctx MSL context.
     * @param masterToken master token. May be untrusted.
     * @param identity entity identity. May be {@code null}.
     * @param encryptionKey encryption key.
     * @param hmacKey HMAC key.
     */
    SessionCryptoContext(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<tokens::MasterToken> masterToken,
            const std::string& identity, const SecretKey& encryptionKey, const SecretKey& hmacKey);

private:
    DISALLOW_IMPLICIT_CONSTRUCTORS(SessionCryptoContext);
};

}}} // namespace netflix::msl::crypto

#endif /* SRC_CRYPTO_SESSIONCRYPTOCONTEXT_H_ */
