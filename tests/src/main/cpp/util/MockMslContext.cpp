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

#include "MockMslContext.h"
#include <crypto/Key.h>
#include <crypto/JcaAlgorithm.h>
#include <crypto/Random.h>
#include <crypto/SymmetricCryptoContext.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <entityauth/PresharedAuthenticationData.h>
#include <entityauth/PresharedProfileAuthenticationData.h>
#include <entityauth/RsaAuthenticationData.h>
#include <entityauth/UnauthenticatedAuthenticationData.h>
#include <entityauth/UnauthenticatedAuthenticationFactory.h>
#include <io/DefaultMslEncoderFactory.h>
#include <keyx/AsymmetricWrappedExchange.h>
#include <keyx/DiffieHellmanExchange.h>
#include <keyx/KeyExchangeScheme.h>
#include <keyx/KeyExchangeFactory.h>
#include <keyx/SymmetricWrappedExchange.h>
#include <msg/MessageCapabilities.h>
#include <MslInternalException.h>
#include <userauth/UserAuthenticationScheme.h>
#include <userauth/UserAuthenticationFactory.h>
#include <stdint.h>
#include <sys/time.h>
#include <util/SimpleMslStore.h>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "../tokens/MockTokenFactory.h"
#include "../entityauth/MockPresharedAuthenticationFactory.h"
#include "../entityauth/MockPresharedProfileAuthenticationFactory.h"
#include "../entityauth/MockRsaAuthenticationFactory.h"
#include "../keyx/MockDiffieHellmanParameters.h"
#include "../userauth/MockEmailPasswordAuthenticationFactory.h"
#include "../userauth/MockUserIdTokenAuthenticationFactory.h"
#include "../util/MockAuthenticationUtils.h"

using netflix::msl::msg::MessageCapabilities;

using namespace std;
using namespace testing;
using namespace netflix::msl;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::keyx;
using namespace netflix::msl::msg;
using namespace netflix::msl::tokens;
using namespace netflix::msl::userauth;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace util {

namespace {

/** MSL encryption key. */
const uint8_t MSL_ENCRYPTION_KEY[] = {
    0x1d, 0x58, 0xf3, 0xb8, 0xf7, 0x47, 0xd1, 0x6a,
    0xb1, 0x93, 0xc4, 0xc0, 0xa6, 0x24, 0xea, 0xcf,
};
/** MSL HMAC key. */
const uint8_t MSL_HMAC_KEY[] = {
    0xd7, 0xae, 0xbf, 0xd5, 0x87, 0x9b, 0xb0, 0xe0,
    0xad, 0x01, 0x6a, 0x4c, 0xf3, 0xcb, 0x39, 0x82,
    0xf5, 0xba, 0x26, 0x0d, 0xa5, 0x20, 0x24, 0x5b,
    0xb4, 0x22, 0x75, 0xbd, 0x79, 0x47, 0x37, 0x0c,
};
/** MSL wrapping key. */
const uint8_t MSL_WRAPPING_KEY[] = {
    0x83, 0xb6, 0x9a, 0x15, 0x80, 0xd3, 0x23, 0xa2,
    0xe7, 0x9d, 0xd9, 0xb2, 0x26, 0x26, 0xb3, 0xf6,
};

template<typename T, size_t S> size_t SizeOf(T(&)[S]) { return S; }
#define BYTE_ARRAY(a) make_shared<ByteArray>(a, a + SizeOf(a))

} // namespace anonymous


MockMslContext::MockMslContext(const EntityAuthenticationScheme& scheme, bool peerToPeer)
: random(make_shared<Random>())
, peerToPeer(peerToPeer)
{
    if (scheme == EntityAuthenticationScheme::PSK)
        entityAuthData = make_shared<PresharedAuthenticationData>(MockPresharedAuthenticationFactory::PSK_ESN);
    else if (scheme == EntityAuthenticationScheme::PSK_PROFILE)
        entityAuthData = make_shared<PresharedProfileAuthenticationData>(MockPresharedProfileAuthenticationFactory::PSK_ESN, MockPresharedProfileAuthenticationFactory::PROFILE);
//    else if (scheme == EntityAuthenticationScheme::X509)
//        entityAuthData = make_shared<X509AuthenticationData>(MockX509AuthenticationFactory::X509_CERT);
    else if (scheme == EntityAuthenticationScheme::RSA)
        entityAuthData = make_shared<RsaAuthenticationData>(MockRsaAuthenticationFactory::RSA_ESN, MockRsaAuthenticationFactory::RSA_PUBKEY_ID);
    else if (scheme == EntityAuthenticationScheme::NONE)
        entityAuthData = make_shared<UnauthenticatedAuthenticationData>("MOCKUNAUTH-ESN");
//    else if (scheme == EntityAuthenticationScheme::NONE_SUFFIXED)
//        entityAuthData = make_shared<UnauthenticatedSuffixedAuthenticationData>("MOCKUNAUTH-ROOT", "MOCKUNAUTH-SUFFIX");

    set<MslConstants::CompressionAlgorithm> algos;
    algos.insert(MslConstants::CompressionAlgorithm::GZIP);
    algos.insert(MslConstants::CompressionAlgorithm::LZW);
    vector<string> languages;
    languages.insert(languages.begin(), "en-US");
    set<MslEncoderFormat> formats;
    formats.insert(MslEncoderFormat::JSON);
    capabilities = make_shared<MessageCapabilities>(algos, languages, formats);

    tokenFactory = make_shared<MockTokenFactory>();
    store = make_shared<SimpleMslStore>();
    encoderFactory = make_shared<DefaultMslEncoderFactory>();

    shared_ptr<DiffieHellmanParameters> params = MockDiffieHellmanParameters::getDefaultParameters();
    authutils = make_shared<MockAuthenticationUtils>();

    entityAuthFactories.insert(make_pair(EntityAuthenticationScheme::PSK, make_shared<MockPresharedAuthenticationFactory>()));
    entityAuthFactories.insert(make_pair(EntityAuthenticationScheme::PSK_PROFILE, make_shared<MockPresharedProfileAuthenticationFactory>()));
    entityAuthFactories.insert(make_pair(EntityAuthenticationScheme::RSA, make_shared<MockRsaAuthenticationFactory>()));
    entityAuthFactories.insert(make_pair(EntityAuthenticationScheme::NONE, make_shared<UnauthenticatedAuthenticationFactory>(authutils)));
//    entityAuthFactories.insert(make_pair(EntityAuthenticationScheme::X509, make_shared<MockX509AuthenticationFactory>()));
//    entityAuthFactories.insert(make_pair(EntityAuthenticationScheme::NONE_SUFFIXED, make_shared<UnauthenticatedSuffixedAuthenticationFactory>(authutils)));
//    entityAuthFactories.insert(make_pair(EntityAuthenticationScheme::MT_PROTECTED, make_shared<MasterTokenProtectedAuthenticationFactory>(authutils)));
//    entityAuthFactories.insert(make_pair(EntityAuthenticationScheme::PROVISIONED, make_shared<ProvisionedAuthenticationFactory>(new MockIdentityProvisioningService(this))));

    userAuthFactories.insert(make_pair(UserAuthenticationScheme::EMAIL_PASSWORD, make_shared<MockEmailPasswordAuthenticationFactory>()));
    userAuthFactories.insert(make_pair(UserAuthenticationScheme::USER_ID_TOKEN, make_shared<MockUserIdTokenAuthenticationFactory>()));

    keyxFactories.insert(make_shared<AsymmetricWrappedExchange>(authutils));
    keyxFactories.insert(make_shared<SymmetricWrappedExchange>(authutils));
    keyxFactories.insert(make_shared<DiffieHellmanExchange>(params, authutils));
}

int64_t MockMslContext::getTime()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    uint64_t ms = static_cast<uint64_t>(tp.tv_sec) * 1000ull + static_cast<uint64_t>(tp.tv_usec) / 1000ull;
    return static_cast<int64_t>(ms);
}

shared_ptr<ICryptoContext> MockMslContext::getMslCryptoContext()
{
	if (!mslCryptoContext) {
	    const SecretKey mslEncryptionKey(BYTE_ARRAY(MSL_ENCRYPTION_KEY), JcaAlgorithm::AES);
	    const SecretKey mslHmacKey(BYTE_ARRAY(MSL_HMAC_KEY), JcaAlgorithm::HMAC_SHA256);
	    const SecretKey mslWrappingKey(BYTE_ARRAY(MSL_WRAPPING_KEY), JcaAlgorithm::AESKW);
	    mslCryptoContext = make_shared<SymmetricCryptoContext>(shared_from_this(), "TestMslKeys", mslEncryptionKey, mslHmacKey, mslWrappingKey);
	}
	return mslCryptoContext;
}

EntityAuthenticationScheme MockMslContext::getEntityAuthenticationScheme(const string& name)
{
    return EntityAuthenticationScheme::getScheme(name);
}

void MockMslContext::addEntityAuthenticationFactory(shared_ptr<EntityAuthenticationFactory> factory)
{
	const EntityAuthenticationScheme scheme = factory->getScheme();
	entityAuthFactories.erase(scheme);
    entityAuthFactories.insert(make_pair(scheme, factory));
}

void MockMslContext::removeEntityAuthenticationFactory(const EntityAuthenticationScheme& scheme)
{
    entityAuthFactories.erase(scheme);
}

shared_ptr<EntityAuthenticationFactory> MockMslContext::getEntityAuthenticationFactory(const EntityAuthenticationScheme& scheme)
{
    map<EntityAuthenticationScheme, shared_ptr<EntityAuthenticationFactory>>::const_iterator it = entityAuthFactories.find(scheme);
    return (it != entityAuthFactories.end()) ? it->second : shared_ptr<EntityAuthenticationFactory>();
}

UserAuthenticationScheme MockMslContext::getUserAuthenticationScheme(const string& name)
{
    return UserAuthenticationScheme::getScheme(name);
}

void MockMslContext::addUserAuthenticationFactory(shared_ptr<UserAuthenticationFactory> factory)
{
	const UserAuthenticationScheme scheme = factory->getScheme();
	userAuthFactories.erase(scheme);
    userAuthFactories.insert(make_pair(scheme, factory));
}

void MockMslContext::removeUserAuthenticationFactory(const UserAuthenticationScheme& scheme)
{
    userAuthFactories.erase(scheme);
}

shared_ptr<UserAuthenticationFactory> MockMslContext::getUserAuthenticationFactory(const UserAuthenticationScheme& scheme)
{
    map<UserAuthenticationScheme, shared_ptr<UserAuthenticationFactory>>::const_iterator it = userAuthFactories.find(scheme);
    return (it != userAuthFactories.end()) ? it->second : shared_ptr<UserAuthenticationFactory>();
}

KeyExchangeScheme MockMslContext::getKeyExchangeScheme(const std::string& name)
{
    return KeyExchangeScheme::getScheme(name);
}

void MockMslContext::addKeyExchangeFactory(shared_ptr<KeyExchangeFactory> factory)
{
    pair<set<shared_ptr<keyx::KeyExchangeFactory>>::iterator, bool> result =
            keyxFactories.insert(factory);
    if (!result.second)
        throw MslInternalException("Could not add KeyExchangeFactory");
}

void MockMslContext::removeKeyExchangeFactories(const KeyExchangeScheme& scheme)
{
    // FIXME: use std::remove_if algorithm?
    for (set<shared_ptr<KeyExchangeFactory>>::iterator it = keyxFactories.begin(); it != keyxFactories.end(); )
    {
        if ((*it)->getScheme() == scheme) {
            keyxFactories.erase(it++);
        }
        else {
            ++it;
        }
    }
}

shared_ptr<KeyExchangeFactory> MockMslContext::getKeyExchangeFactory(const KeyExchangeScheme& scheme)
{
    for (set<shared_ptr<KeyExchangeFactory>>::const_iterator it = keyxFactories.begin(); it != keyxFactories.end(); ++it)
    {
        if ((*it)->getScheme() == scheme)
            return *it;
    }
    return shared_ptr<KeyExchangeFactory>();
}

set<shared_ptr<KeyExchangeFactory>> MockMslContext::getKeyExchangeFactories()
{
    return keyxFactories;
}

}}} // namespace netflix::msl::util
