/**
 * Copyright (c) 2018 Netflix, Inc.  All rights reserved.
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
#ifndef SRC_ENTITYAUTH_ECCAUTHENTICATIONFACTORY_H_
#define SRC_ENTITYAUTH_ECCAUTHENTICATIONFACTORY_H_

#include <entityauth/EntityAuthenticationFactory.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <entityauth/EccStore.h>

#include <memory>
#include <string>

namespace netflix {
namespace msl {
namespace crypto { class ICryptoContext; }
namespace io { class MslObject; }
namespace util { class AuthenticationUtils; class MslContext; }
namespace entityauth {

class EntityAuthenticationData;

/**
 * An ECC public key store contains trusted ECC public and private keys.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class EccAuthenticationFactory : public EntityAuthenticationFactory
{
public:
    virtual ~EccAuthenticationFactory() {}

    /** @inheritDoc */
    virtual std::shared_ptr<EntityAuthenticationData> createData(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<io::MslObject> entityAuthMo);

    /** @inheritDoc */
    virtual std::shared_ptr<crypto::ICryptoContext> getCryptoContext(
            std::shared_ptr<util::MslContext> ctx, std::shared_ptr<EntityAuthenticationData> authdata);

protected:
    /**
     * <p>Construct a new ECC asymmetric keys authentication factory
     * instance.</p>
     *
     * @param store ECC key store.
     * @param authutils authentication utilities.
     */
    EccAuthenticationFactory(std::shared_ptr<EccStore> store, std::shared_ptr<util::AuthenticationUtils> authutils);

    /**
     * <p>Construct a new ECC asymmetric keys authentication factory instance
     * with the specified key pair ID for the local entity. The ECC key store
     * must contain a private key for the local entity (a public key is
     * optional).</p>
     *
     * @param keyPairId local entity key pair ID. Empty string indicates none.
     * @param store ECC key store.
     * @param authutils authentication utilities.
     */
    EccAuthenticationFactory(const std::string& keyPairId, std::shared_ptr<EccStore> store, std::shared_ptr<util::AuthenticationUtils> authutils);

private:
    /** Local entity key pair ID. */
    const std::string keyPairId_;
    /** ECC key store. */
    std::shared_ptr<EccStore> store_;
    /** Authentication utilities. */
    std::shared_ptr<util::AuthenticationUtils> authutils_;
};

}}} // namespace netflix::msl::entityauth

#endif /* SRC_ENTITYAUTH_ECCAUTHENTICATIONFACTORY_H_ */
