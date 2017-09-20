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

#ifndef TEST_ENTITYAUTH_MOCKPRESHAREDPROFILEAUTHENTICATIONFACTORY_H_
#define TEST_ENTITYAUTH_MOCKPRESHAREDPROFILEAUTHENTICATIONFACTORY_H_

#include <entityauth/EntityAuthenticationFactory.h>
#include <crypto/Key.h>

namespace netflix {
namespace msl {
namespace entityauth {

/**
 * Test pre-shared keys profile authentication factory.
 */
class MockPresharedProfileAuthenticationFactory: public entityauth::EntityAuthenticationFactory
{
public:
    virtual ~MockPresharedProfileAuthenticationFactory() {}

    /** PSK ESN. */
    static const std::string PSK_ESN;
    /** PSK ESN 2. */
    static const std::string PSK_ESN2;
    /** Profile. */
    static const std::string PROFILE;

    /**
     * Create a new test pre-shared keys profile authentication factory.
     */
    MockPresharedProfileAuthenticationFactory();

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.io.MslObject)
     */
    virtual std::shared_ptr<entityauth::EntityAuthenticationData> createData(std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<io::MslObject> entityAuthMo);

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.PresharedAuthenticationFactory#getCryptoContext(com.netflix.msl.util.MslContext, com.netflix.msl.entityauth.EntityAuthenticationData)
     */
    virtual std::shared_ptr<crypto::ICryptoContext> getCryptoContext(
            std::shared_ptr<util::MslContext> ctx,
            std::shared_ptr<entityauth::EntityAuthenticationData> authdata);

private:
    std::shared_ptr<ByteArray> PSK_KPE;
    std::shared_ptr<ByteArray> PSK_KPH;
    std::shared_ptr<ByteArray> PSK_KPE2;
    std::shared_ptr<ByteArray> PSK_KPH2;
public:
    /** Kpe/Kph/Kpw #1. */
    const crypto::SecretKey KPE, KPH, KPW;
    /** Kpe/Kph/Kpw #2. */
    const crypto::SecretKey KPE2, KPH2, KPW2;

};

}}} // namespace netflix::msl::entityauth

#endif /* TEST_ENTITYAUTH_MOCKPRESHAREDPROFILEAUTHENTICATIONFACTORY_H_ */
