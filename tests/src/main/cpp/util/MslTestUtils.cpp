/**
 * Copyright (c) 2016-2020 Netflix, Inc.  All rights reserved.
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

#include "MslTestUtils.h"

#include <crypto/IRandom.h>
#include <crypto/NullCryptoContext.h>
#include <Date.h>
#include <crypto/OpenSslLib.h>
#include <entityauth/EntityAuthenticationData.h>
#include <io/MslEncodable.h>
#include <io/MslEncoderFactory.h>
#include <MslCryptoException.h>
#include <MslInternalException.h>
#include <tokens/MasterToken.h>
#include <tokens/MslUser.h>
#include <tokens/ServiceToken.h>
#include <tokens/UserIdToken.h>
#include <util/MslContext.h>
#include <algorithm>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <gtest/gtest.h>
#include <entityauth/MockPresharedAuthenticationFactory.h>
#include <util/ScopedDisposer.h>

using namespace std;
using namespace testing;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;

namespace netflix {

typedef vector<uint8_t> ByteArray;

namespace msl {
namespace util {

namespace {

template<typename T, size_t N> T* begin(T (&arr)[N]) { return &arr[0];     }
template<typename T, size_t N> T* end(T (&arr)[N])   { return &arr[0] + N; }

/** Wrapping key derivation algorithm salt. */
const unsigned char saltAry[] = {
    0x02, 0x76, 0x17, 0x98, 0x4f, 0x62, 0x27, 0x53,
    0x9a, 0x63, 0x0b, 0x89, 0x7c, 0x01, 0x7d, 0x69
};

/** Wrapping key derivation algorithm info. */
static const unsigned char infoAry[] = {
    0x80, 0x9f, 0x82, 0xa7, 0xad, 0xdf, 0x54, 0x8d,
    0x3e, 0xa9, 0xdd, 0x06, 0x7f, 0xf9, 0xbb, 0x91
};

/** Base service token name. */
const string SERVICE_TOKEN_NAME = "serviceTokenName";
/**
 * Maximum number of service tokens to randomly generate. This needs to be
 * large enough to statistically create the applicable set of service
 * tokens for the tests.
 */
const int32_t NUM_SERVICE_TOKENS = 12;

} // namespace anonymous

namespace MslTestUtils {

shared_ptr<MslObject> toMslObject(shared_ptr<MslEncoderFactory> encoder, shared_ptr<MslEncodable> encode)
{
    shared_ptr<ByteArray> encoding = encode->toMslEncoding(encoder, encoder->getPreferredFormat());
    return encoder->parseObject(encoding);
}

pair<PublicKey,PrivateKey> generateRsaKeys(const string& algo, int length)
{
	static const unsigned long publicExponent = 65537;
	uint32_t retryCount = 0;
	static const uint32_t MAX_RETRIES = 4;
	while (true)
	{
		ScopedDisposer<RSA, void, RSA_free> rsa(RSA_generate_key(length, publicExponent, 0, 0));
		if (!rsa.isEmpty())
		{
			if (RSA_check_key(rsa.get()) == 1)
			{
				// public key in SPKI format
				int keyLen = i2d_RSA_PUBKEY(rsa.get(), NULL);
				shared_ptr<ByteArray> spki = make_shared<ByteArray>(keyLen);
				unsigned char * buf = &(*spki)[0];
				if (!i2d_RSA_PUBKEY(rsa.get(), &buf))
					throw MslInternalException("i2d_RSA_PUBKEY failed");
				PublicKey publicKey(spki, algo);

				// private key in PKCS#8 format
				ScopedDisposer<EVP_PKEY, void, EVP_PKEY_free> pkey(EVP_PKEY_new());
				if (pkey.isEmpty())
					throw MslInternalException("EVP_PKEY_new failed");
				if (!EVP_PKEY_set1_RSA(pkey.get(), rsa.get()))
					throw MslInternalException("EVP_PKEY_set1_RSA failed");
				ScopedDisposer<PKCS8_PRIV_KEY_INFO, void, PKCS8_PRIV_KEY_INFO_free> p8inf(EVP_PKEY2PKCS8(pkey.get()));
				if (p8inf.isEmpty())
					throw MslInternalException("PKCS8_PRIV_KEY_INFO_free failed");
				int outLen = i2d_PKCS8_PRIV_KEY_INFO(p8inf.get(), NULL);
				if (outLen <= 0)
					throw MslInternalException("i2d_PKCS8_PRIV_KEY_INFO failed");
				shared_ptr<ByteArray> pkcs8 = make_shared<ByteArray>(outLen);
				buf = &(*pkcs8)[0];
				if (!i2d_PKCS8_PRIV_KEY_INFO(p8inf.get(), &buf))
					throw MslInternalException("i2d_PKCS8_PRIV_KEY_INFO failed");
				PrivateKey privateKey(pkcs8, algo);

				// done with key generation
				return make_pair(publicKey, privateKey);
			}
			else
			{
				if (retryCount++ > MAX_RETRIES)
					throw MslInternalException("Too many retries while generating RSA key pair");
			}
		}
	}
}

shared_ptr<ByteArray> deriveWrappingKey(shared_ptr<ByteArray> encryptionKey, shared_ptr<ByteArray> hmacKey)
{
    // Derive Kpw key data from Kpe and Kph, according to the following algorithm:
    // Kpw = trunc_128(HMAC-SHA256(HMAC-SHA256(salt, cat(Kpe, Kph)), info))
    // where the first argument to HMAC-SHA256 is the key.
    // salt = 02 76 17 98 4f 62 27 53 9a 63 0b 89 7c 01 7d 69
    // info = 80 9f 82 a7 ad df 54 8d 3e a9 dd 06 7f f9 bb 91
    ensureOpenSslInit();
    try {

        const ByteArray salt(begin(saltAry), end(saltAry));
        const ByteArray info(begin(infoAry), end(infoAry));

        // cat Kpe and Kph
        ByteArray catK(*encryptionKey);
        catK.insert(catK.end(), hmacKey->begin(), hmacKey->end());

        // first HMAC(salt, catK)
        ByteArray sig1;
        signHmacSha256(salt, catK, sig1);

        // second HMAC(first HMAC, info)
        ByteArray sig2;
        signHmacSha256(sig1, info, sig2);

        // truncation and final output
         assert(sig2.size() > 128/8);
         shared_ptr<ByteArray> wrappingKey = make_shared<ByteArray>(sig2.begin(), sig2.begin() + 128/8);
         return wrappingKey;

    } catch (const MslCryptoException& e) {
        throw MslInternalException("Wrapping key derivation failed", e);
    }
}

shared_ptr<MasterToken> getMasterToken(shared_ptr<MslContext> ctx,
        int64_t sequenceNumber, int64_t serialNumber)
{
    shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() + 10000);
    shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 20000);
    shared_ptr<EntityAuthenticationData> entityAuthData = ctx->getEntityAuthenticationData(MslContext::ReauthCode::ENTITYDATA_REAUTH);
    const string identity = entityAuthData->getIdentity();
    const SecretKey encryptionKey(MockPresharedAuthenticationFactory::KPE);
    const SecretKey hmacKey(MockPresharedAuthenticationFactory::KPH);
    return make_shared<MasterToken>(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, make_shared<MslObject>(), identity, encryptionKey, hmacKey);
}

shared_ptr<MasterToken> getUntrustedMasterToken(shared_ptr<MslContext> ctx)
{
    shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() + 10000);
    shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 20000);
    shared_ptr<EntityAuthenticationData> entityAuthData = ctx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID);
    const string identity = entityAuthData->getIdentity();
    const SecretKey encryptionKey = MockPresharedAuthenticationFactory::KPE;
    const SecretKey hmacKey = MockPresharedAuthenticationFactory::KPH;
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, renewalWindow, expiration, 1L, 1L, shared_ptr<io::MslObject>(), identity, encryptionKey, hmacKey);
    shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
    shared_ptr<MslObject> mo = toMslObject(encoder, masterToken);
    shared_ptr<ByteArray> signature = mo->getBytes("signature");
    ++(*signature)[1];
    mo->put("signature", signature);
    return make_shared<MasterToken>(ctx, mo);
}

shared_ptr<UserIdToken> getUserIdToken(shared_ptr<MslContext> ctx, shared_ptr<MasterToken> masterToken,
        int64_t serialNumber, shared_ptr<MslUser> user)
{
    shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() + 10000);
    shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 20000);
    return make_shared<UserIdToken>(ctx, renewalWindow, expiration, masterToken, serialNumber, shared_ptr<MslObject>(), user);
}

shared_ptr<UserIdToken> getUntrustedUserIdToken(shared_ptr<MslContext> ctx,
        shared_ptr<MasterToken> masterToken, int64_t serialNumber,
        shared_ptr<MslUser> user)
{
    shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() + 10000);
    shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 20000);
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx, renewalWindow, expiration, masterToken, serialNumber, shared_ptr<MslObject>(), user);
    shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
    shared_ptr<MslObject> mo = toMslObject(encoder, userIdToken);
    shared_ptr<ByteArray> signature = mo->getBytes("signature");
    ++(*signature)[1];
    mo->put("signature", signature);
    return make_shared<UserIdToken>(ctx, mo, masterToken);
}

set<shared_ptr<ServiceToken>> getServiceTokens(shared_ptr<MslContext> ctx,
        shared_ptr<MasterToken> masterToken, shared_ptr<UserIdToken> userIdToken)
{
    shared_ptr<IRandom> random = ctx->getRandom();
    shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
    set<shared_ptr<ServiceToken>> serviceTokens;
    int32_t numTokens = std::max(NUM_SERVICE_TOKENS, 3);
    for (int32_t i = 0; i < numTokens; ++i) {
        stringstream ss;
        ss << SERVICE_TOKEN_NAME << random->nextInt();
        const string name = ss.str();
        shared_ptr<ByteArray> data = make_shared<ByteArray>(32);
        random->nextBytes(*data);

        // Make sure one of each type of token is included.
        // Otherwise pick a random type.
        const shared_ptr<MasterToken> nullMasterToken;
        const shared_ptr<UserIdToken> nullUserIdToken;
        const int32_t type = (i < 3) ? i : random->nextInt(3);
        switch (type) {
            case 0:
                serviceTokens.insert(make_shared<ServiceToken>(ctx, name, data, nullMasterToken, nullUserIdToken, false, MslConstants::CompressionAlgorithm::NOCOMPRESSION, cryptoContext));
                break;
            case 1:
                serviceTokens.insert(make_shared<ServiceToken>(ctx, name, data, masterToken, nullUserIdToken, false, MslConstants::CompressionAlgorithm::NOCOMPRESSION, cryptoContext));
                break;
            case 2:
                serviceTokens.insert(make_shared<ServiceToken>(ctx, name, data, masterToken, userIdToken, false, MslConstants::CompressionAlgorithm::NOCOMPRESSION, cryptoContext));
                break;
            default:
                assert(false);
        }
    }
    return serviceTokens;
}

set<shared_ptr<ServiceToken>> getMasterBoundServiceTokens(shared_ptr<MslContext> ctx,
		shared_ptr<MasterToken> masterToken)
{
	shared_ptr<IRandom> random = ctx->getRandom();
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	set<shared_ptr<ServiceToken>> tokens;
	for (int count = random->nextInt(NUM_SERVICE_TOKENS); count >= 0; --count) {
        stringstream ss;
        ss << SERVICE_TOKEN_NAME << random->nextInt();
        const string name = ss.str();
		shared_ptr<ByteArray> data = make_shared<ByteArray>(8);
		random->nextBytes(*data);
		shared_ptr<ServiceToken> token = make_shared<ServiceToken>(ctx, name, data, masterToken, shared_ptr<UserIdToken>(), false, MslConstants::CompressionAlgorithm::NOCOMPRESSION, cryptoContext);
		tokens.insert(token);
	}
	return tokens;
}

set<shared_ptr<ServiceToken>> getUserBoundServiceTokens(shared_ptr<MslContext> ctx,
		shared_ptr<MasterToken> masterToken, shared_ptr<UserIdToken> userIdToken)
{
	shared_ptr<IRandom> random = ctx->getRandom();
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	set<shared_ptr<ServiceToken>> tokens;
	for (int count = random->nextInt(NUM_SERVICE_TOKENS); count >= 0; --count) {
        stringstream ss;
        ss << SERVICE_TOKEN_NAME << random->nextInt();
        const string name = ss.str();
		shared_ptr<ByteArray> data = make_shared<ByteArray>(8);
		random->nextBytes(*data);
		shared_ptr<ServiceToken> token = make_shared<ServiceToken>(ctx, name, data, masterToken, userIdToken, false, MslConstants::CompressionAlgorithm::NOCOMPRESSION, cryptoContext);
		tokens.insert(token);
	}
	return tokens;
}

}}}} // namespace netflix::msl::MslTestUtils
