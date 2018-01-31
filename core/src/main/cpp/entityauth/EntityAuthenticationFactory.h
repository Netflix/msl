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

#ifndef SRC_ENTITYAUTH_ENTITYAUTHENTICATIONFACTORY_H_
#define SRC_ENTITYAUTH_ENTITYAUTHENTICATIONFACTORY_H_

#include <entityauth/EntityAuthenticationScheme.h>
#include <memory>

namespace netflix {
namespace msl {
namespace util { class MslContext; }
namespace io { class MslObject; }
namespace crypto { class ICryptoContext; }
namespace entityauth {

class EntityAuthenticationData;

/**
 * A entity authentication factory creates authentication data instances and
 * authenticators for a specific entity authentication scheme.
 */
class EntityAuthenticationFactory
{
public:
    virtual ~EntityAuthenticationFactory() {}

    /**
     * @return the entity authentication scheme this factory is for.
     */
    EntityAuthenticationScheme getScheme() { return scheme_; }

    /**
     * Construct a new entity authentication data instance from the provided
     * MSL object.
     *
     * @param ctx MSL context.
     * @param entityAuthMo the MSL object.
     * @return the entity authentication data.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslCryptoException if there is an error with the entity
     *         authentication data cryptography.
     * @throws MslEntityAuthException if there is an error creating the entity
     *         authentication data.
     */
    virtual std::shared_ptr<EntityAuthenticationData> createData(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<io::MslObject> entityAuthMo) = 0;

    /**
     * Create a crypto context that can be used to encrypt/decrypt and
     * authenticate data from the entity. The implementation of this function
     * must, by necessity, authenticate the entity authentication data.
     *
     * @param ctx MSL context.
     * @param authdata the authentication data.
     * @return the entity crypto context.
     * @throws MslCryptoException if there is an error instantiating the crypto
     *         context.
     * @throws MslEntityAuthException if there is an error with the entity
     *         authentication data.
     */
    virtual std::shared_ptr<crypto::ICryptoContext> getCryptoContext(
            std::shared_ptr<util::MslContext> ctx, std::shared_ptr<EntityAuthenticationData> authdata) = 0;

protected:
    /**
     * Create a new entity authentication factory for the specified scheme.
     *
     * @param scheme the entity authentication scheme.
     */
    EntityAuthenticationFactory(const EntityAuthenticationScheme& scheme) : scheme_(scheme) {}

private:
    /** The factory's entity authentication scheme. */
    const EntityAuthenticationScheme scheme_;
};

}}} // namespace netflix::msl::entityauth

#endif /* SRC_ENTITYAUTH_ENTITYAUTHENTICATIONFACTORY_H_ */
