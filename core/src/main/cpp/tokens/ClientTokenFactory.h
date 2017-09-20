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

#ifndef SRC_TOKENS_CLIENTTOKENFACTORY_H_
#define SRC_TOKENS_CLIENTTOKENFACTORY_H_

#include <tokens/TokenFactory.h>

namespace netflix {
namespace msl {
namespace tokens {

/**
 * This class should be used by trusted network clients for the token factory.
 * Since trusted network clients do not issue tokens the mamority of these
 * methods either return under the assumption everything should be accepted or
 * trusted, or throw exceptions if the operation should never occur.
 */
class ClientTokenFactory: public TokenFactory
{
public:
    virtual ~ClientTokenFactory() {}
    ClientTokenFactory() {}

    virtual MslError isMasterTokenRevoked(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MasterToken> masterToken);

    virtual MslError acceptNonReplayableId(std::shared_ptr<util::MslContext> ctx,
             std::shared_ptr<MasterToken> masterToken, int64_t nonReplayableId);

    virtual std::shared_ptr<MasterToken> createMasterToken(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData,
            const crypto::SecretKey& encryptionKey, const crypto::SecretKey& hmacKey,
            std::shared_ptr<io::MslObject> issuerData);

    virtual MslError isMasterTokenRenewable(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MasterToken> masterToken);

    virtual std::shared_ptr<MasterToken> renewMasterToken(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MasterToken> masterToken,
            const crypto::SecretKey& encryptionKey,
            const crypto::SecretKey& hmacKey,
            std::shared_ptr<io::MslObject> issuerData);

    virtual MslError isUserIdTokenRevoked(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MasterToken> masterToken,
            std::shared_ptr<UserIdToken> userIdToken);

    virtual std::shared_ptr<UserIdToken> createUserIdToken(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<MslUser> user, std::shared_ptr<MasterToken> masterToken);

    virtual std::shared_ptr<UserIdToken> renewUserIdToken(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<UserIdToken> userIdToken, std::shared_ptr<MasterToken> masterToken);

    virtual std::shared_ptr<MslUser> createUser(std::shared_ptr<util::MslContext> ctx,
            const std::string& userdata);
};

}}} // namespace netflix::msl::tokens

#endif /* SRC_TOKENS_CLIENTTOKENFACTORY_H_ */
