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

#ifndef TEST_ENTITYAUTH_MOCKRSAAUTHENTICATIONFACTORY_H_
#define TEST_ENTITYAUTH_MOCKRSAAUTHENTICATIONFACTORY_H_

#include <gmock/gmock.h>
#include <entityauth/EntityAuthenticationFactory.h>
#include <crypto/Key.h>
#include <string>

// namespace aliases, to reduce clutter
namespace nm = netflix::msl;
namespace nmu = nm::util;
namespace nme = nm::entityauth;
namespace nmc = nm::crypto;
namespace nmi = nm::io;

typedef std::vector<uint8_t> ByteArray;

namespace netflix {
namespace msl {
namespace entityauth {

/**
 * Test RSA asymmetric keys authentication factory.
 */
class MockRsaAuthenticationFactory : public nme::EntityAuthenticationFactory
{
public:
    /** RSA ESN. */
    static const std::string RSA_ESN;
    /** RSA public key ID. */
    static const std::string RSA_PUBKEY_ID;
    /** RSA public key. */
    static const nmc::PublicKey RSA_PUBKEY;
    /** RSA private key. */
    static const nmc::PrivateKey RSA_PRIVKEY;

public:
    MockRsaAuthenticationFactory()
    : nme::EntityAuthenticationFactory(nme::EntityAuthenticationScheme::RSA)
    {}

    std::shared_ptr<nme::EntityAuthenticationData> createData(std::shared_ptr<nmu::MslContext> ctx,
            std::shared_ptr<nmi::MslObject> entityAuthMo);
    std::shared_ptr<nmc::ICryptoContext> getCryptoContext(std::shared_ptr<nmu::MslContext> ctx,
            std::shared_ptr<nme::EntityAuthenticationData> authdata);
};

}}} // namespace netflix::msl::entityauth

#endif /* TEST_ENTITYAUTH_MOCKRSAAUTHENTICATIONFACTORY_H_ */
