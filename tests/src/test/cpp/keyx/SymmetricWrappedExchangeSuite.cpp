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

#include <entityauth/PresharedAuthenticationData.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <keyx/KeyExchangeFactory.h>
#include <keyx/KeyExchangeScheme.h>
#include <keyx/KeyRequestData.h>
#include <keyx/SymmetricWrappedExchange.h>
#include <Macros.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslEntityAuthException.h>
#include <MslInternalException.h>
#include <MslKeyExchangeException.h>
#include <MslMasterTokenException.h>
#include <tokens/MasterToken.h>
#include <memory>
#include <string>

#include "../entityauth/MockPresharedAuthenticationFactory.h"
#include "../util/MockMslContext.h"
#include "../util/MslTestUtils.h"
#include "../util/MockAuthenticationUtils.h"

using namespace std;
using namespace testing;
using namespace netflix::msl;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace keyx {

namespace {

/** Key key exchange scheme. */
const string KEY_SCHEME = "scheme";
/** Key key request data-> */
const string KEY_KEYDATA = "keydata";

/** Key symmetric key ID. */
const string KEY_KEY_ID = "keyid";
/** Key wrapped encryption key. */
const string KEY_ENCRYPTION_KEY = "encryptionkey";
/** Key wrapped HMAC key. */
const string KEY_HMAC_KEY = "hmackey";

/** Key master token. */
const string KEY_MASTER_TOKEN = "mastertoken";

} // namespace anonymous

/**
 * Symmetric wrapped key exchange unit tests.
 */

// This class holds expensive stuff that we only want to create once.
class TestSingleton
{
public:
    static shared_ptr<MockMslContext> getMockPskMslContext() {
        static shared_ptr<MockMslContext> theInstance;
        if (!theInstance)
            theInstance = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
        return theInstance;
    }
    static shared_ptr<MockMslContext> getMockUnauthMslContext() {
        static shared_ptr<MockMslContext> theInstance;
        if (!theInstance)
            theInstance = make_shared<MockMslContext>(EntityAuthenticationScheme::NONE, false);
        return theInstance;
    }
};

// This class holds the stuff common to the suites in this file.
class BaseTest
{
public:
    BaseTest()
    : pskCtx(TestSingleton::getMockPskMslContext())
    , unauthCtx(TestSingleton::getMockUnauthMslContext())
    , random(pskCtx->getRandom())
    , ENCODER_FORMAT(MslEncoderFormat::JSON)
    , encoder(pskCtx->getMslEncoderFactory())
    , PSK_MASTER_TOKEN(MslTestUtils::getMasterToken(pskCtx, 1, 1))
    , ENCRYPTION_KEY(make_shared<ByteArray>(16))
    , HMAC_KEY(make_shared<ByteArray>(32))
    {
    }
protected:
    virtual ~BaseTest() {}
    /** Preshared keys entity context. */
    shared_ptr<MockMslContext> pskCtx;
    /** Unauthenticated (server) entity context. */
    shared_ptr<MockMslContext> unauthCtx;
    /** Random. */
    shared_ptr<IRandom> random;
    /** MSL encoder format. */
    const MslEncoderFormat ENCODER_FORMAT;
    /** MSL encoder factory-> */
    shared_ptr<MslEncoderFactory> encoder;

    shared_ptr<MasterToken> PSK_MASTER_TOKEN;
    shared_ptr<ByteArray> ENCRYPTION_KEY;
    shared_ptr<ByteArray> HMAC_KEY;
};

// =============================================================================
/** Request data unit tests. */
// =============================================================================

class SweRequestDataTest : public ::testing::Test, protected BaseTest
{
};

TEST_F(SweRequestDataTest, ctorsPsk)
{
    SymmetricWrappedExchange::RequestData req(SymmetricWrappedExchange::KeyId::PSK);
    EXPECT_EQ(KeyExchangeScheme::SYMMETRIC_WRAPPED, req.getKeyExchangeScheme());
    EXPECT_EQ(SymmetricWrappedExchange::KeyId::PSK, req.getKeyId());
    shared_ptr<MslObject> keydata = req.getKeydata(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(keydata);

    SymmetricWrappedExchange::RequestData moReq(keydata);
    EXPECT_EQ(req.getKeyExchangeScheme(), moReq.getKeyExchangeScheme());
    EXPECT_EQ(req.getKeyId(), moReq.getKeyId());
    shared_ptr<MslObject> moKeydata = moReq.getKeydata(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moKeydata);
    EXPECT_EQ(*keydata, *moKeydata);
}

TEST_F(SweRequestDataTest, ctorsSession)
{
    SymmetricWrappedExchange::RequestData req(SymmetricWrappedExchange::KeyId::SESSION);
    EXPECT_EQ(KeyExchangeScheme::SYMMETRIC_WRAPPED, req.getKeyExchangeScheme());
    EXPECT_EQ(SymmetricWrappedExchange::KeyId::SESSION, req.getKeyId());
    shared_ptr<MslObject> keydata = req.getKeydata(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(keydata);

    SymmetricWrappedExchange::RequestData moReq(keydata);
    EXPECT_EQ(req.getKeyExchangeScheme(), moReq.getKeyExchangeScheme());
    EXPECT_EQ(req.getKeyId(), moReq.getKeyId());
    shared_ptr<MslObject> moKeydata = moReq.getKeydata(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moKeydata);
    EXPECT_EQ(*keydata, *moKeydata);
}

TEST_F(SweRequestDataTest, mslObject)
{
    shared_ptr<SymmetricWrappedExchange::RequestData> req = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, req);
    EXPECT_EQ(KeyExchangeScheme::SYMMETRIC_WRAPPED.toString(), mo->getString(KEY_SCHEME));
    shared_ptr<MslObject> keydata = mo->getMslObject(KEY_KEYDATA, encoder);
    EXPECT_EQ(SymmetricWrappedExchange::KeyId::PSK.toString(), keydata->getString(KEY_KEY_ID));
}

TEST_F(SweRequestDataTest, create)
{
    shared_ptr<SymmetricWrappedExchange::RequestData> data = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, data);
    shared_ptr<KeyRequestData> keyRequestData = KeyRequestData::create(pskCtx, mo);
    EXPECT_TRUE(keyRequestData);
    EXPECT_TRUE(instanceof<SymmetricWrappedExchange::RequestData>(keyRequestData.get()));

    shared_ptr<SymmetricWrappedExchange::RequestData> moData = dynamic_pointer_cast<SymmetricWrappedExchange::RequestData>(keyRequestData);
    EXPECT_EQ(data->getKeyExchangeScheme(), moData->getKeyExchangeScheme());
    EXPECT_EQ(data->getKeyId(), moData->getKeyId());
}

TEST_F(SweRequestDataTest, missingKeyId)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError::MSL_PARSE_ERROR);

    SymmetricWrappedExchange::RequestData req(SymmetricWrappedExchange::KeyId::PSK);
    shared_ptr<MslObject> keydata = req.getKeydata(encoder, ENCODER_FORMAT);

    EXPECT_FALSE(keydata->remove(KEY_KEY_ID).isNull());

    try {
        SymmetricWrappedExchange::RequestData foo(keydata);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(SweRequestDataTest, invalidKeyId)
{
//    thrown.expect(MslKeyExchangeException.class);
//    thrown.expectMslError(MslError::UNIDENTIFIED_KEYX_KEY_ID);

    SymmetricWrappedExchange::RequestData req(SymmetricWrappedExchange::KeyId::PSK);
    shared_ptr<MslObject> keydata = req.getKeydata(encoder, ENCODER_FORMAT);

    keydata->put<string>(KEY_KEY_ID, "x");

    try {
        SymmetricWrappedExchange::RequestData foo(keydata);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslKeyExchangeException& e) {
        EXPECT_EQ(MslError::UNIDENTIFIED_KEYX_KEY_ID, e.getError());
    }
}

TEST_F(SweRequestDataTest, equalsKeyId)
{
    shared_ptr<SymmetricWrappedExchange::RequestData> dataA = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
    shared_ptr<SymmetricWrappedExchange::RequestData> dataB = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::SESSION);
    shared_ptr<SymmetricWrappedExchange::RequestData> dataA2 = make_shared<SymmetricWrappedExchange::RequestData>(dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    EXPECT_TRUE(dataA->equals(dataA2));
    EXPECT_TRUE(dataA2->equals(dataA));
}

// =============================================================================
/** Response data unit tests. */
// =============================================================================

class SweResponseDataTest : public ::testing::Test, protected BaseTest
{
};

TEST_F(SweResponseDataTest, ctors)
{
    SymmetricWrappedExchange::ResponseData resp(PSK_MASTER_TOKEN, SymmetricWrappedExchange::KeyId::PSK, ENCRYPTION_KEY, HMAC_KEY);
    EXPECT_EQ(ENCRYPTION_KEY, resp.getEncryptionKey());
    EXPECT_EQ(HMAC_KEY, resp.getHmacKey());
    EXPECT_EQ(KeyExchangeScheme::SYMMETRIC_WRAPPED, resp.getKeyExchangeScheme());
    EXPECT_EQ(SymmetricWrappedExchange::KeyId::PSK, resp.getKeyId());
    EXPECT_EQ(PSK_MASTER_TOKEN, resp.getMasterToken());
    shared_ptr<MslObject> keydata = resp.getKeydata(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(keydata);

    SymmetricWrappedExchange::ResponseData moResp(PSK_MASTER_TOKEN, keydata);
    EXPECT_EQ(resp.getEncryptionKey(), moResp.getEncryptionKey());
    EXPECT_EQ(resp.getHmacKey(), moResp.getHmacKey());
    EXPECT_EQ(resp.getKeyExchangeScheme(), moResp.getKeyExchangeScheme());
    EXPECT_EQ(resp.getKeyId(), moResp.getKeyId());
    EXPECT_EQ(resp.getMasterToken(), moResp.getMasterToken());
    shared_ptr<MslObject> moKeydata = resp.getKeydata(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moKeydata);
    EXPECT_EQ(*keydata, *moKeydata);
}

TEST_F(SweResponseDataTest, mslObject)
{
    shared_ptr<SymmetricWrappedExchange::ResponseData> resp = make_shared<SymmetricWrappedExchange::ResponseData>(PSK_MASTER_TOKEN, SymmetricWrappedExchange::KeyId::PSK, ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, resp);
    EXPECT_EQ(KeyExchangeScheme::SYMMETRIC_WRAPPED.toString(), mo->getString(KEY_SCHEME));
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(pskCtx, mo->getMslObject(KEY_MASTER_TOKEN, encoder));
    EXPECT_EQ(*PSK_MASTER_TOKEN, *masterToken);
    shared_ptr<MslObject> keydata = mo->getMslObject(KEY_KEYDATA, encoder);
    EXPECT_EQ(SymmetricWrappedExchange::KeyId::PSK.toString(), keydata->getString(KEY_KEY_ID));
    EXPECT_EQ(*ENCRYPTION_KEY, *keydata->getBytes(KEY_ENCRYPTION_KEY));
    EXPECT_EQ(*HMAC_KEY, *keydata->getBytes(KEY_HMAC_KEY));
}

TEST_F(SweResponseDataTest, create)
{
    shared_ptr<SymmetricWrappedExchange::ResponseData> data = make_shared<SymmetricWrappedExchange::ResponseData>(PSK_MASTER_TOKEN, SymmetricWrappedExchange::KeyId::PSK, ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, data);
    shared_ptr<KeyResponseData> keyResponseData = KeyResponseData::create(pskCtx, mo);
    EXPECT_TRUE(keyResponseData);
    EXPECT_TRUE(instanceof<SymmetricWrappedExchange::ResponseData>(keyResponseData.get()));

    shared_ptr<SymmetricWrappedExchange::ResponseData> moData = dynamic_pointer_cast<SymmetricWrappedExchange::ResponseData>(keyResponseData);
    EXPECT_EQ(*data->getEncryptionKey(), *moData->getEncryptionKey());
    EXPECT_EQ(*data->getHmacKey(), *moData->getHmacKey());
    EXPECT_EQ(data->getKeyExchangeScheme(), moData->getKeyExchangeScheme());
    EXPECT_EQ(data->getKeyId(), moData->getKeyId());
    EXPECT_EQ(*data->getMasterToken(), *moData->getMasterToken());
}

TEST_F(SweResponseDataTest, missingKeyId)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError::MSL_PARSE_ERROR);

    SymmetricWrappedExchange::ResponseData resp(PSK_MASTER_TOKEN, SymmetricWrappedExchange::KeyId::PSK, ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<MslObject> keydata = resp.getKeydata(encoder, ENCODER_FORMAT);

    EXPECT_FALSE(keydata->remove(KEY_KEY_ID).isNull());

    try {
        SymmetricWrappedExchange::ResponseData foo(PSK_MASTER_TOKEN, keydata);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(SweResponseDataTest, missingEncryptionKey)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError::MSL_PARSE_ERROR);

    SymmetricWrappedExchange::ResponseData resp(PSK_MASTER_TOKEN, SymmetricWrappedExchange::KeyId::PSK, ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<MslObject> keydata = resp.getKeydata(encoder, ENCODER_FORMAT);

    EXPECT_FALSE(keydata->remove(KEY_ENCRYPTION_KEY).isNull());

    try {
        SymmetricWrappedExchange::ResponseData foo(PSK_MASTER_TOKEN, keydata);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(SweResponseDataTest, missingHmacKey)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError::MSL_PARSE_ERROR);

    SymmetricWrappedExchange::ResponseData resp(PSK_MASTER_TOKEN, SymmetricWrappedExchange::KeyId::PSK, ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<MslObject> keydata = resp.getKeydata(encoder, ENCODER_FORMAT);

    EXPECT_FALSE(keydata->remove(KEY_HMAC_KEY).isNull());

    try {
        SymmetricWrappedExchange::ResponseData foo(PSK_MASTER_TOKEN, keydata);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(SweResponseDataTest, equalsMasterToken)
{
    shared_ptr<MasterToken>masterTokenA = MslTestUtils::getMasterToken(pskCtx, 1, 1);
    shared_ptr<MasterToken>masterTokenB = MslTestUtils::getMasterToken(pskCtx, 1, 2);
    shared_ptr<SymmetricWrappedExchange::ResponseData> dataA = make_shared<SymmetricWrappedExchange::ResponseData>(masterTokenA, SymmetricWrappedExchange::KeyId::PSK, ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<SymmetricWrappedExchange::ResponseData> dataB = make_shared<SymmetricWrappedExchange::ResponseData>(masterTokenB, SymmetricWrappedExchange::KeyId::PSK, ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<SymmetricWrappedExchange::ResponseData> dataA2 = make_shared<SymmetricWrappedExchange::ResponseData>(masterTokenA, dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    EXPECT_TRUE(dataA->equals(dataA2));
    EXPECT_TRUE(dataA2->equals(dataA));
}

TEST_F(SweResponseDataTest, equalsKeyId)
{
    shared_ptr<SymmetricWrappedExchange::ResponseData> dataA = make_shared<SymmetricWrappedExchange::ResponseData>(PSK_MASTER_TOKEN, SymmetricWrappedExchange::KeyId::PSK, ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<SymmetricWrappedExchange::ResponseData> dataB = make_shared<SymmetricWrappedExchange::ResponseData>(PSK_MASTER_TOKEN, SymmetricWrappedExchange::KeyId::SESSION, ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<SymmetricWrappedExchange::ResponseData> dataA2 = make_shared<SymmetricWrappedExchange::ResponseData>(PSK_MASTER_TOKEN, dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    EXPECT_TRUE(dataA->equals(dataA2));
    EXPECT_TRUE(dataA2->equals(dataA));
}

TEST_F(SweResponseDataTest, equalsEncryptionKey)
{
	shared_ptr<ByteArray> encryptionKeyA = make_shared<ByteArray>(); *encryptionKeyA = *ENCRYPTION_KEY;
	shared_ptr<ByteArray> encryptionKeyB = make_shared<ByteArray>(); *encryptionKeyB = *ENCRYPTION_KEY;
    ++(*encryptionKeyB)[0];
    shared_ptr<SymmetricWrappedExchange::ResponseData> dataA = make_shared<SymmetricWrappedExchange::ResponseData>(PSK_MASTER_TOKEN, SymmetricWrappedExchange::KeyId::PSK, encryptionKeyA, HMAC_KEY);
    shared_ptr<SymmetricWrappedExchange::ResponseData> dataB = make_shared<SymmetricWrappedExchange::ResponseData>(PSK_MASTER_TOKEN, SymmetricWrappedExchange::KeyId::PSK, encryptionKeyB, HMAC_KEY);
    shared_ptr<SymmetricWrappedExchange::ResponseData> dataA2 = make_shared<SymmetricWrappedExchange::ResponseData>(PSK_MASTER_TOKEN, dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    EXPECT_TRUE(dataA->equals(dataA2));
    EXPECT_TRUE(dataA2->equals(dataA));
}

TEST_F(SweResponseDataTest, equalsHmacKey)
{
	shared_ptr<ByteArray> hmacKeyA = make_shared<ByteArray>(); *hmacKeyA = *HMAC_KEY;
	shared_ptr<ByteArray> hmacKeyB = make_shared<ByteArray>(); *hmacKeyB = *HMAC_KEY;
    ++(*hmacKeyB)[0];
    shared_ptr<SymmetricWrappedExchange::ResponseData> dataA = make_shared<SymmetricWrappedExchange::ResponseData>(PSK_MASTER_TOKEN, SymmetricWrappedExchange::KeyId::PSK, ENCRYPTION_KEY, hmacKeyA);
    shared_ptr<SymmetricWrappedExchange::ResponseData> dataB = make_shared<SymmetricWrappedExchange::ResponseData>(PSK_MASTER_TOKEN, SymmetricWrappedExchange::KeyId::PSK, ENCRYPTION_KEY, hmacKeyB);
    shared_ptr<SymmetricWrappedExchange::ResponseData> dataA2 = make_shared<SymmetricWrappedExchange::ResponseData>(PSK_MASTER_TOKEN, dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    EXPECT_TRUE(dataA->equals(dataA2));
    EXPECT_TRUE(dataA2->equals(dataA));
}

// =============================================================================
/** Key exchange factory unit tests. */
// =============================================================================

namespace {

/**
 * Fake key request data for the asymmetric wrapped key exchange
 * scheme.
 */
struct FakeKeyRequestData : public KeyRequestData
{
    /** Create a new fake key request data-> */
    FakeKeyRequestData() : KeyRequestData(KeyExchangeScheme::SYMMETRIC_WRAPPED) {}

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyRequestData#getKeydata(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    virtual shared_ptr<MslObject> getKeydata(shared_ptr<MslEncoderFactory>, const MslEncoderFormat&) const
    {
        return shared_ptr<MslObject>();
    }
};

/**
 * Fake key response data for the asymmetric wrapped key exchange
 * scheme.
 */
struct FakeKeyResponseData : public KeyResponseData
{
    /** Create a new fake key response data-> */
    FakeKeyResponseData(shared_ptr<MasterToken> mt) : KeyResponseData(mt, KeyExchangeScheme::SYMMETRIC_WRAPPED) {}

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.KeyResponseData#getKeydata(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    virtual shared_ptr<MslObject> getKeydata(shared_ptr<MslEncoderFactory>, const MslEncoderFormat&) const
    {
        return shared_ptr<MslObject>();
    }
};

/**
 * @param ctx MSL context.
 * @param identity entity identity.
 * @param encryptionKey master token encryption key.
 * @param hmacKey master token HMAC key.
 * @return a new master token.
 * @throws MslException if the master token is constructed incorrectly.
 * @throws MslEncoderException if there is an error editing the data->
 */
shared_ptr<MasterToken> getUntrustedMasterToken(shared_ptr<MslContext> ctx, const string& identity, const SecretKey& encryptionKey, const SecretKey& hmacKey)
{
    shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() + 1000);
    shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 2000);
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, renewalWindow, expiration, 1L, 1L, shared_ptr<MslObject>(), identity, encryptionKey, hmacKey);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(ctx->getMslEncoderFactory(), masterToken);
    shared_ptr<ByteArray> signature = mo->getBytes("signature");
    ++(*signature)[1];
    mo->put("signature", signature);
    shared_ptr<MasterToken>untrustedMasterToken = make_shared<MasterToken>(ctx, mo);
    return untrustedMasterToken;
}

} // namespace anonymous

class SymmetricWrappedKeyExchangeTest : public ::testing::Test, protected BaseTest
{
public:
    SymmetricWrappedKeyExchangeTest()
    : authutils(make_shared<MockAuthenticationUtils>())
    , factory(make_shared<SymmetricWrappedExchange>(authutils))
    , entityAuthData(make_shared<PresharedAuthenticationData>(MockPresharedAuthenticationFactory::PSK_ESN))
    {}

protected:
    virtual void SetUp()
    {
        authutils.reset();
        pskCtx->getMslStore()->clearCryptoContexts();
        pskCtx->getMslStore()->clearServiceTokens();
    }
    /** Authentication utilities. */
    shared_ptr<MockAuthenticationUtils> authutils;
    /** Key exchange factory-> */
    shared_ptr<KeyExchangeFactory> factory;
    /** Entity authentication data */
    shared_ptr<EntityAuthenticationData> entityAuthData;
};

TEST_F(SymmetricWrappedKeyExchangeTest, factory)
{
    EXPECT_EQ(KeyExchangeScheme::SYMMETRIC_WRAPPED, factory->getScheme());
}

TEST_F(SymmetricWrappedKeyExchangeTest, generatePskInitialResponse)
{
    shared_ptr<KeyRequestData> keyRequestData = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData);
    EXPECT_TRUE(keyxData);
    EXPECT_TRUE(keyxData->cryptoContext);
    EXPECT_TRUE(keyxData->keyResponseData);

    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    EXPECT_EQ(KeyExchangeScheme::SYMMETRIC_WRAPPED, keyResponseData->getKeyExchangeScheme());
    shared_ptr<MasterToken>masterToken = keyResponseData->getMasterToken();
    EXPECT_TRUE(masterToken);
    EXPECT_EQ(MockPresharedAuthenticationFactory::PSK_ESN, masterToken->getIdentity());
}

// This test is disabled in java
#if 0
TEST_F(SymmetricWrappedKeyExchangeTest, generateSessionInitialResponse)
{
    shared_ptr<KeyRequestData> keyRequestData(SymmetricWrappedExchange::KeyId::SESSION);
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN);
    EXPECT_TRUE(keyxData);
    EXPECT_TRUE(keyxData->cryptoContext);
    EXPECT_TRUE(keyxData->keyResponseData);

    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    EXPECT_EQ(KeyExchangeScheme::SYMMETRIC_WRAPPED, keyResponseData->getKeyExchangeScheme());
    shared_ptr<MasterToken>masterToken = keyResponseData->getMasterToken();
    EXPECT_TRUE(masterToken);
    EXPECT_EQ(PSK_MASTER_TOKEN->getIdentity(), masterToken->getIdentity());
}
#endif

TEST_F(SymmetricWrappedKeyExchangeTest, invalidPskInitialResponse)
{
//@Test(expected = MslEntityAuthException.class)
    shared_ptr<KeyRequestData> keyRequestData = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
    shared_ptr<EntityAuthenticationData> entityAuthData = make_shared<PresharedAuthenticationData>(MockPresharedAuthenticationFactory::PSK_ESN + "x");
    EXPECT_THROW(factory->generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData), MslEntityAuthException);
}

TEST_F(SymmetricWrappedKeyExchangeTest, wrongRequestInitialResponse)
{
//@Test(expected = MslInternalException.class)
    shared_ptr<KeyRequestData> keyRequestData = make_shared<FakeKeyRequestData>();
    EXPECT_THROW(factory->generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData), MslInternalException);
}

TEST_F(SymmetricWrappedKeyExchangeTest, generatePskSubsequentResponse)
{
    shared_ptr<KeyRequestData> keyRequestData = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN);
    EXPECT_TRUE(keyxData);
    EXPECT_TRUE(keyxData->cryptoContext);
    EXPECT_TRUE(keyxData->keyResponseData);

    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    EXPECT_EQ(KeyExchangeScheme::SYMMETRIC_WRAPPED, keyResponseData->getKeyExchangeScheme());
    shared_ptr<MasterToken>masterToken = keyResponseData->getMasterToken();
    EXPECT_TRUE(masterToken);
    EXPECT_EQ(PSK_MASTER_TOKEN->getIdentity(), masterToken->getIdentity());
    EXPECT_EQ(PSK_MASTER_TOKEN->getSerialNumber(), masterToken->getSerialNumber());
    EXPECT_EQ(PSK_MASTER_TOKEN->getSequenceNumber() + 1, masterToken->getSequenceNumber());
}

// This test is disabled in java
#if 0
TEST_F(SymmetricWrappedKeyExchangeTest, generateSessionSubsequentResponse)
{
    shared_ptr<KeyRequestData> keyRequestData = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::SESSION);
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN);
    EXPECT_TRUE(keyxData);
    EXPECT_TRUE(keyxData->cryptoContext);
    EXPECT_TRUE(keyxData->keyResponseData);

    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    EXPECT_EQ(KeyExchangeScheme::SYMMETRIC_WRAPPED, keyResponseData->getKeyExchangeScheme());
    shared_ptr<MasterToken>masterToken = keyResponseData->getMasterToken();
    EXPECT_TRUE(masterToken);
    EXPECT_EQ(PSK_MASTER_TOKEN->getIdentity(), masterToken->getIdentity());
    EXPECT_EQ(PSK_MASTER_TOKEN->getSerialNumber(), masterToken->getSerialNumber());
    EXPECT_EQ(PSK_MASTER_TOKEN->getSequenceNumber() + 1, masterToken->getSequenceNumber());
}
#endif

TEST_F(SymmetricWrappedKeyExchangeTest, untrustedMasterTokenPskSubsequentResponse)
{
//    thrown.expect(MslMasterTokenException.class);
//    thrown.expectMslError(MslError::MASTERTOKEN_UNTRUSTED);

    shared_ptr<KeyRequestData> keyRequestData = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
    const string identity = MockPresharedAuthenticationFactory::PSK_ESN;
    const SecretKey encryptionKey = MockPresharedAuthenticationFactory::KPE;
    const SecretKey hmacKey = MockPresharedAuthenticationFactory::KPH;
    shared_ptr<MasterToken>masterToken = getUntrustedMasterToken(unauthCtx, identity, encryptionKey, hmacKey);
    try {
        factory->generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, masterToken);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslMasterTokenException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_UNTRUSTED, e.getError());
    }
}

TEST_F(SymmetricWrappedKeyExchangeTest, wrongRequestSubsequentResponse)
{
//@Test(expected = MslInternalException.class)
    shared_ptr<KeyRequestData> keyRequestData = make_shared<FakeKeyRequestData>();
    EXPECT_THROW(factory->generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN), MslInternalException);
}

TEST_F(SymmetricWrappedKeyExchangeTest, untrustedMasterTokenSubsequentResponse)
{
//@Test(expected = MslMasterTokenException.class)
    shared_ptr<KeyRequestData> keyRequestData = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::SESSION);
    const string identity = MockPresharedAuthenticationFactory::PSK_ESN;
    const SecretKey encryptionKey = MockPresharedAuthenticationFactory::KPE;
    const SecretKey hmacKey = MockPresharedAuthenticationFactory::KPH;
    shared_ptr<MasterToken>masterToken = getUntrustedMasterToken(unauthCtx, identity, encryptionKey, hmacKey);
    EXPECT_THROW(factory->generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, masterToken), MslMasterTokenException);
}

TEST_F(SymmetricWrappedKeyExchangeTest, getPskCryptoContext)
{
    shared_ptr<KeyRequestData> keyRequestData = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData);
    shared_ptr<ICryptoContext> requestCryptoContext = keyxData->cryptoContext;
    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    shared_ptr<ICryptoContext> responseCryptoContext = factory->getCryptoContext(pskCtx, keyRequestData, keyResponseData, shared_ptr<MasterToken>());
    EXPECT_TRUE(responseCryptoContext);

    shared_ptr<ByteArray> data = make_shared<ByteArray>(32);
    random->nextBytes(*data);

    // Ciphertext won't always be equal depending on how it was
    // enveloped. So we cannot check for equality or inequality.
    shared_ptr<ByteArray> requestCiphertext = requestCryptoContext->encrypt(data, encoder, ENCODER_FORMAT);
    shared_ptr<ByteArray> responseCiphertext = responseCryptoContext->encrypt(data, encoder, ENCODER_FORMAT);
    EXPECT_NE(*data, *requestCiphertext);
    EXPECT_NE(*data, *responseCiphertext);

    // Signatures should always be equal.
    shared_ptr<ByteArray> requestSignature = requestCryptoContext->sign(data, encoder, ENCODER_FORMAT);
    shared_ptr<ByteArray> responseSignature = responseCryptoContext->sign(data, encoder, ENCODER_FORMAT);
    EXPECT_NE(*data, *requestSignature);
    EXPECT_NE(*data, *responseSignature);
    EXPECT_EQ(*requestSignature, *responseSignature);

    // Plaintext should always be equal to the original message.
    shared_ptr<ByteArray> requestPlaintext = requestCryptoContext->decrypt(responseCiphertext, encoder);
    shared_ptr<ByteArray> responsePlaintext = responseCryptoContext->decrypt(requestCiphertext, encoder);
    EXPECT_FALSE(requestPlaintext->empty());
    EXPECT_EQ(*data, *requestPlaintext);
    EXPECT_EQ(*requestPlaintext, *responsePlaintext);

    // Verification should always succeed.
    EXPECT_TRUE(requestCryptoContext->verify(data, responseSignature, encoder));
    EXPECT_TRUE(responseCryptoContext->verify(data, requestSignature, encoder));
}

// This test is disabled in java
#if 0
TEST_F(SymmetricWrappedKeyExchangeTest, getSessionCryptoContext)
{
    shared_ptr<KeyRequestData> keyRequestData(SymmetricWrappedExchange::KeyId::SESSION);
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN);
    shared_ptr<ICryptoContext> requestCryptoContext = keyxData->cryptoContext;
    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    shared_ptr<ICryptoContext> responseCryptoContext = factory->getCryptoContext(pskCtx, keyRequestData, keyResponseData, PSK_MASTER_TOKEN);
    EXPECT_TRUE(responseCryptoContext);

    shared_ptr<ByteArray> data = make_shared<ByteArray>(32);
    random->nextBytes(*data);

    shared_ptr<ByteArray> requestCiphertext = requestCryptoContext->encrypt(data, encoder, ENCODER_FORMAT);
    shared_ptr<ByteArray> responseCiphertext = responseCryptoContext->encrypt(data, encoder, ENCODER_FORMAT);
    EXPECT_NE(data, requestCiphertext);
    EXPECT_NE(data, responseCiphertext);

    shared_ptr<ByteArray> requestSignature = requestCryptoContext->sign(data, encoder, ENCODER_FORMAT);
    shared_ptr<ByteArray> responseSignature = responseCryptoContext->sign(data, encoder, ENCODER_FORMAT);
    EXPECT_NE(data, requestSignature);
    EXPECT_NE(data, responseSignature);

    shared_ptr<ByteArray> requestPlaintext = requestCryptoContext->decrypt(responseCiphertext, encoder);
    shared_ptr<ByteArray> responsePlaintext = responseCryptoContext->decrypt(requestCiphertext, encoder);
    EXPECT_TRUE(requestPlaintext);
    EXPECT_EQ(data, requestPlaintext);
    EXPECT_EQ(requestPlaintext, responsePlaintext);

    EXPECT_TRUE(requestCryptoContext->verify(data, responseSignature, encoder));
    EXPECT_TRUE(responseCryptoContext->verify(data, requestSignature, encoder));
}
#endif

// This test is disabled in java
#if 0
TEST_F(SymmetricWrappedKeyExchangeTest, missingMasterTokenCryptoContext)
{
//    thrown.expect(MslKeyExchangeException.class);
//    thrown.expectMslError(MslError::KEYX_MASTER_TOKEN_MISSING);

    shared_ptr<KeyRequestData> keyRequestData(SymmetricWrappedExchange::KeyId::SESSION);
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN);
    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    try {
        factory->getCryptoContext(pskCtx, keyRequestData, keyResponseData, shared_ptr<MasterToken>());
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslMasterTokenException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_UNTRUSTED, e.getError());
    }
}
#endif

TEST_F(SymmetricWrappedKeyExchangeTest, wrongRequestCryptoContext)
{
//@Test(expected = MslInternalException.class)
    shared_ptr<KeyRequestData> keyRequestData = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData);
    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;

    shared_ptr<KeyRequestData> fakeKeyRequestData = make_shared<FakeKeyRequestData>();
    EXPECT_THROW(factory->getCryptoContext(pskCtx, fakeKeyRequestData, keyResponseData, shared_ptr<MasterToken>()), MslInternalException);
}

TEST_F(SymmetricWrappedKeyExchangeTest, wrongResponseCryptoContext)
{
//@Test(expected = MslInternalException.class)
    shared_ptr<KeyRequestData> keyRequestData = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
    shared_ptr<KeyResponseData> fakeKeyResponseData = make_shared<FakeKeyResponseData>(PSK_MASTER_TOKEN);
    EXPECT_THROW(factory->getCryptoContext(pskCtx, keyRequestData, fakeKeyResponseData, shared_ptr<MasterToken>()), MslInternalException);
}

TEST_F(SymmetricWrappedKeyExchangeTest, keyIdMismatchCryptoContext)
{
//    thrown.expect(MslKeyExchangeException.class);
//    thrown.expectMslError(MslError::KEYX_RESPONSE_REQUEST_MISMATCH);

    shared_ptr<KeyRequestData> keyRequestData = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData);
    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    shared_ptr<MasterToken>masterToken = keyResponseData->getMasterToken();

    shared_ptr<KeyResponseData> mismatchedKeyResponseData = make_shared<SymmetricWrappedExchange::ResponseData>(masterToken, SymmetricWrappedExchange::KeyId::SESSION, ENCRYPTION_KEY, HMAC_KEY);

    try {
        factory->getCryptoContext(pskCtx, keyRequestData, mismatchedKeyResponseData, shared_ptr<MasterToken>());
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslKeyExchangeException& e) {
        EXPECT_EQ(MslError::KEYX_RESPONSE_REQUEST_MISMATCH, e.getError());
    }
}

TEST_F(SymmetricWrappedKeyExchangeTest, invalidWrappedEncryptionKeyCryptoContext)
{
//@Test(expected = MslCryptoException.class)
    shared_ptr<KeyRequestData> keyRequestData = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData);
    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    shared_ptr<MasterToken>masterToken = keyResponseData->getMasterToken();

    shared_ptr<MslObject> keydata = keyResponseData->getKeydata(encoder, ENCODER_FORMAT);
    shared_ptr<ByteArray> wrappedEncryptionKey = keydata->getBytes(KEY_ENCRYPTION_KEY);
    ++(*wrappedEncryptionKey)[wrappedEncryptionKey->size()-1];
    keydata->put(KEY_ENCRYPTION_KEY, wrappedEncryptionKey);
    shared_ptr<ByteArray> wrappedHmacKey = keydata->getBytes(KEY_HMAC_KEY);

    shared_ptr<KeyResponseData> invalidKeyResponseData = make_shared<SymmetricWrappedExchange::ResponseData>(masterToken, SymmetricWrappedExchange::KeyId::PSK, wrappedEncryptionKey, wrappedHmacKey);
    EXPECT_THROW(factory->getCryptoContext(pskCtx, keyRequestData, invalidKeyResponseData, shared_ptr<MasterToken>()), MslCryptoException);
}

TEST_F(SymmetricWrappedKeyExchangeTest, invalidWrappedHmacKeyCryptoContext)
{
//@Test(expected = MslCryptoException.class)
    shared_ptr<KeyRequestData> keyRequestData = make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK);
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData);
    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    shared_ptr<MasterToken>masterToken = keyResponseData->getMasterToken();

    shared_ptr<MslObject> keydata = keyResponseData->getKeydata(encoder, ENCODER_FORMAT);
    shared_ptr<ByteArray> wrappedHmacKey = keydata->getBytes(KEY_HMAC_KEY);
    ++(*wrappedHmacKey)[wrappedHmacKey->size()-1];
    keydata->put(KEY_HMAC_KEY, wrappedHmacKey);
    shared_ptr<ByteArray> wrappedEncryptionKey = keydata->getBytes(KEY_ENCRYPTION_KEY);

    shared_ptr<KeyResponseData> invalidKeyResponseData = make_shared<SymmetricWrappedExchange::ResponseData>(masterToken, SymmetricWrappedExchange::KeyId::PSK, wrappedEncryptionKey, wrappedHmacKey);
    EXPECT_THROW(factory->getCryptoContext(pskCtx, keyRequestData, invalidKeyResponseData, shared_ptr<MasterToken>()), MslCryptoException);
}

}}} // namespace netflix::msl::keyx
