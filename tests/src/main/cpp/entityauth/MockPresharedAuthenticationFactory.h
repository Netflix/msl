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

#ifndef TEST_ENTITYAUTH_MOCKPRESHAREDAUTHENTICATIONFACTORY_H_
#define TEST_ENTITYAUTH_MOCKPRESHAREDAUTHENTICATIONFACTORY_H_

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
 * Mock pre-shared keys authentication factory.
 */
class MockPresharedAuthenticationFactory : public nme::EntityAuthenticationFactory
{
public:
    static const std::shared_ptr<ByteArray> PSK_KPE, PSK_KPH;
    static const std::string PSK_ESN;
    static const nmc::SecretKey KPE, KPH, KPW;
    static const std::shared_ptr<ByteArray> PSK_KPE2, PSK_KPH2;
    static const std::string PSK_ESN2;
    static const nmc::SecretKey KPE2, KPH2, KPW2;

public:
    MockPresharedAuthenticationFactory()
    : nme::EntityAuthenticationFactory(nme::EntityAuthenticationScheme::PSK)
    {}

    std::shared_ptr<nme::EntityAuthenticationData> createData(std::shared_ptr<nmu::MslContext> ctx,
            std::shared_ptr<nmi::MslObject> entityAuthMo);
    std::shared_ptr<nmc::ICryptoContext> getCryptoContext(std::shared_ptr<nmu::MslContext> ctx,
            std::shared_ptr<nme::EntityAuthenticationData> authdata);
};

}}} // namespace netflix::msl::entityauth

#endif /* TEST_ENTITYAUTH_MOCKPRESHAREDAUTHENTICATIONFACTORY_H_ */
