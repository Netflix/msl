/**
 * Copyright (c) 2016-2018 Netflix, Inc.  All rights reserved.
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
#include <entityauth/EntityAuthenticationFactory.h>
#include <crypto/Key.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <memory>
#include <string>

namespace netflix {
namespace msl {
namespace crypto { class ICryptoContext; }
namespace io { class MslObject; }
namespace util { class MslContext; }
namespace entityauth {

/**
 * Test ECC asymmetric keys authentication factory.
 */
class MockEccAuthenticationFactory : public EntityAuthenticationFactory
{
public:
	virtual ~MockEccAuthenticationFactory() {}

    /** ECC ESN. */
    static const std::string ECC_ESN;
    /** ECC public key ID. */
    static const std::string ECC_PUBKEY_ID;
    /** ECC public key. */
    static const crypto::PublicKey ECC_PUBKEY;
    /** ECC private key. */
    static const crypto::PrivateKey ECC_PRIVKEY;

    /**
     * Create a new test ECC authentication factory.
     */
    MockEccAuthenticationFactory()
    	: EntityAuthenticationFactory(EntityAuthenticationScheme::ECC)
    {}

    /** @inheritDoc */
    virtual std::shared_ptr<EntityAuthenticationData> createData(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<io::MslObject> entityAuthMo);

    /** @inheritDoc */
    virtual std::shared_ptr<crypto::ICryptoContext> getCryptoContext(
            std::shared_ptr<util::MslContext> ctx, std::shared_ptr<EntityAuthenticationData> authdata);
};

}}} // namespace netflix::msl::entityauth
