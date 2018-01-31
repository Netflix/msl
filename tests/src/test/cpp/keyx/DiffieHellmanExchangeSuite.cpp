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

#include <keyx/DiffieHellmanExchange.h>
#include <gtest/gtest.h>
#include <crypto/OpenSslLib.h>
#include <entityauth/PresharedAuthenticationData.h>
#include <keyx/KeyExchangeFactory.h>
#include <keyx/KeyExchangeScheme.h>
#include <keyx/KeyRequestData.h>
#include <keyx/KeyResponseData.h>
#include <keyx/SymmetricWrappedExchange.h>
#include <Macros.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslEntityAuthException.h>
#include <MslInternalException.h>
#include <MslKeyExchangeException.h>
#include <MslMasterTokenException.h>
#include <tokens/MasterToken.h>
#include <util/Hex.h>
#include <algorithm>
#include <memory>
#include <string>

#include <entityauth/MockPresharedAuthenticationFactory.h>
#include <util/MockMslContext.h>
#include <util/MslTestUtils.h>
#include <util/MockAuthenticationUtils.h>
#include <keyx/MockDiffieHellmanParameters.h>

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

typedef DiffieHellmanExchange::RequestData RequestData;
typedef DiffieHellmanExchange::ResponseData ResponseData;

namespace {

/** Key key exchange scheme. */
const string KEY_SCHEME = "scheme";
/** Key key request data-> */
const string KEY_KEYDATA = "keydata";
/** Key Diffie-Hellman parameters ID. */
const string KEY_PARAMETERS_ID = "parametersid";
/** Key Diffie-Hellman public key. */
const string KEY_PUBLIC_KEY = "publickey";

/**
 * If the provided byte array begins with a null byte this function simply
 * returns the original array. Otherwise a new array is created that is a
 * copy of the original array with a null byte prepended, and this new array
 * is returned.
 *
 * @param b the original array.
 * @return the resulting byte array.
 */
ByteArray prependNullByte(const ByteArray& b) {
    if (b[0] == 0x00)
        return b;
    ByteArray result(b.size() + 1);
    result[0] = 0x00;
    copy(b.begin(), b.end(), result.begin()+1);
    return result;
}

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
};

// This class holds the stuff common to the suites in this file.
class BaseTest
{
public:
    BaseTest()
    : ctx(TestSingleton::getMockPskMslContext())
    , random(ctx->getRandom())
    , encoder(ctx->getMslEncoderFactory())
    , ENCODER_FORMAT(MslEncoderFormat::JSON)
    , MASTER_TOKEN(MslTestUtils::getMasterToken(ctx, 1, 1))
    , PARAMETERS_ID(MockDiffieHellmanParameters::DEFAULT_ID())
    {
        shared_ptr<DiffieHellmanParameters> params = MockDiffieHellmanParameters::getDefaultParameters();
        const DHParameterSpec paramSpec = params->getParameterSpec(PARAMETERS_ID);
        ByteArray tmp1, tmp2;
        dhGenKeyPair(*paramSpec.getP(), *paramSpec.getG(), tmp1, tmp2);
        REQUEST_PUBLIC_KEY = make_shared<ByteArray>(tmp1);
        REQUEST_PRIVATE_KEY = make_shared<PrivateKey>(make_shared<ByteArray>(tmp2), "DH");
        dhGenKeyPair(*paramSpec.getP(), *paramSpec.getG(), tmp1, tmp2);
        RESPONSE_PUBLIC_KEY = make_shared<ByteArray>(tmp1);
        RESPONSE_PRIVATE_KEY = make_shared<PrivateKey>(make_shared<ByteArray>(tmp2), "DH");
    }
protected:
    virtual ~BaseTest() {}
    /** MSL context. */
    shared_ptr<MslContext> ctx;
    /** Random. */
    shared_ptr<IRandom> random;
    /** MSL encoder factory-> */
    shared_ptr<MslEncoderFactory> encoder;
    MslEncoderFormat ENCODER_FORMAT;

    shared_ptr<MasterToken> MASTER_TOKEN;
    const string PARAMETERS_ID;
    shared_ptr<ByteArray> REQUEST_PUBLIC_KEY;
    shared_ptr<PrivateKey> REQUEST_PRIVATE_KEY;
    shared_ptr<ByteArray> RESPONSE_PUBLIC_KEY;
    shared_ptr<PrivateKey> RESPONSE_PRIVATE_KEY;
};

}  // namespace anonymous

// =============================================================================
/** Request data unit tests. */
// =============================================================================

class DhRequestDataTest : public ::testing::Test, public BaseTest
{
};

TEST_F(DhRequestDataTest, ctors)
{
    const RequestData req(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    EXPECT_EQ(KeyExchangeScheme::DIFFIE_HELLMAN, req.getKeyExchangeScheme());
    EXPECT_EQ(PARAMETERS_ID, req.getParametersId());
    EXPECT_EQ(REQUEST_PRIVATE_KEY, req.getPrivateKey());
    EXPECT_EQ(prependNullByte(*REQUEST_PUBLIC_KEY), *req.getPublicKey());
    shared_ptr<MslObject> keydata = req.getKeydata(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(keydata);

    const RequestData moReq(keydata);
    EXPECT_EQ(req.getKeyExchangeScheme(), moReq.getKeyExchangeScheme());
    EXPECT_EQ(req.getParametersId(), moReq.getParametersId());
    EXPECT_FALSE(moReq.getPrivateKey());
    EXPECT_EQ(*req.getPublicKey(), *moReq.getPublicKey());
    shared_ptr<MslObject> moKeydata = moReq.getKeydata(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moKeydata);
    EXPECT_EQ(*keydata, *moKeydata);
}

TEST_F(DhRequestDataTest, mslObject)
{
    shared_ptr<RequestData> req = make_shared<RequestData>(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, req);
    EXPECT_EQ(KeyExchangeScheme::DIFFIE_HELLMAN.toString(), mo->getString(KEY_SCHEME));
    shared_ptr<MslObject> keydata = mo->getMslObject(KEY_KEYDATA, encoder);
    EXPECT_EQ(PARAMETERS_ID, keydata->getString(KEY_PARAMETERS_ID));
    EXPECT_EQ(prependNullByte(*REQUEST_PUBLIC_KEY), *keydata->getBytes(KEY_PUBLIC_KEY));
}

TEST_F(DhRequestDataTest, create)
{
    shared_ptr<RequestData> data = make_shared<RequestData>(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, data);
    shared_ptr<KeyRequestData> keyRequestData = KeyRequestData::create(ctx, mo);
    EXPECT_TRUE(keyRequestData);
    EXPECT_TRUE(instanceof<RequestData>(keyRequestData));

    shared_ptr<RequestData> moData = dynamic_pointer_cast<RequestData>(keyRequestData);
    EXPECT_EQ(data->getKeyExchangeScheme(), moData->getKeyExchangeScheme());
    EXPECT_EQ(data->getParametersId(), moData->getParametersId());
    EXPECT_FALSE(moData->getPrivateKey());
    EXPECT_EQ(*data->getPublicKey(), *moData->getPublicKey());
}

TEST_F(DhRequestDataTest, missingParametersId)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<RequestData> req = make_shared<RequestData>(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    shared_ptr<MslObject> keydata = req->getKeydata(encoder, ENCODER_FORMAT);

    EXPECT_FALSE(keydata->remove(KEY_PARAMETERS_ID).isNull());

    try {
        new RequestData(keydata);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(DhRequestDataTest, missingPublicKey)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<RequestData> req = make_shared<RequestData>(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    shared_ptr<MslObject> keydata = req->getKeydata(encoder, ENCODER_FORMAT);

    EXPECT_FALSE(keydata->remove(KEY_PUBLIC_KEY).isNull());

    try {
        new RequestData(keydata);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(DhRequestDataTest, invalidPublicKey)
{
//    thrown.expect(MslKeyExchangeException.class);
//    thrown.expectMslError(MslError.KEYX_INVALID_PUBLIC_KEY);

    shared_ptr<RequestData> req = make_shared<RequestData>(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    shared_ptr<MslObject> keydata = req->getKeydata(encoder, ENCODER_FORMAT);

    keydata->put(KEY_PUBLIC_KEY, make_shared<ByteArray>());

    try {
        new RequestData(keydata);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslKeyExchangeException& e) {
        EXPECT_EQ(MslError::KEYX_INVALID_PUBLIC_KEY, e.getError());
    }
}

TEST_F(DhRequestDataTest, equalsParametersId)
{
    shared_ptr<RequestData> dataA = make_shared<RequestData>(PARAMETERS_ID + "A", REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    shared_ptr<RequestData> dataB = make_shared<RequestData>(PARAMETERS_ID + "B", REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    shared_ptr<RequestData> dataA2 = make_shared<RequestData>(dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    // The private keys don't transfer via the JSON constructor.
    EXPECT_FALSE(dataA->equals(dataA2));
    EXPECT_FALSE(dataA2->equals(dataA));
}

TEST_F(DhRequestDataTest, equalsPublicKey)
{
    shared_ptr<RequestData> dataA = make_shared<RequestData>(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    shared_ptr<RequestData> dataB = make_shared<RequestData>(PARAMETERS_ID, RESPONSE_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    shared_ptr<RequestData> dataA2 = make_shared<RequestData>(dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    // The private keys don't transfer via the JSON constructor.
    EXPECT_FALSE(dataA->equals(dataA2));
    EXPECT_FALSE(dataA2->equals(dataA));
}

TEST_F(DhRequestDataTest, equalsPrivateKey)
{
    shared_ptr<RequestData> dataA = make_shared<RequestData>(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    shared_ptr<RequestData> dataB = make_shared<RequestData>(PARAMETERS_ID, REQUEST_PUBLIC_KEY, RESPONSE_PRIVATE_KEY);
    shared_ptr<RequestData> dataA2 = make_shared<RequestData>(dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    // The private keys don't transfer via the JSON constructor.
    EXPECT_FALSE(dataA->equals(dataA2));
    EXPECT_FALSE(dataA2->equals(dataA));
}

// =============================================================================
/** Response data unit tests. */
// =============================================================================

class DhResponseDataTest : public ::testing::Test, public BaseTest
{
public:
    DhResponseDataTest() : KEY_MASTER_TOKEN("mastertoken") {}
protected:
    /** Key master token. */
    const string KEY_MASTER_TOKEN;
};

TEST_F(DhResponseDataTest, ctors)
{
    shared_ptr<ResponseData> resp = make_shared<ResponseData>(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
    EXPECT_EQ(KeyExchangeScheme::DIFFIE_HELLMAN, resp->getKeyExchangeScheme());
    EXPECT_EQ(PARAMETERS_ID, resp->getParametersId());
    EXPECT_EQ(prependNullByte(*RESPONSE_PUBLIC_KEY), *resp->getPublicKey());
    shared_ptr<MslObject> keydata = resp->getKeydata(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(keydata);

    shared_ptr<ResponseData> moResp = make_shared<ResponseData>(MASTER_TOKEN, keydata);
    EXPECT_EQ(resp->getKeyExchangeScheme(), moResp->getKeyExchangeScheme());
    EXPECT_EQ(*resp->getMasterToken(), *moResp->getMasterToken());
    EXPECT_EQ(resp->getParametersId(), moResp->getParametersId());
    EXPECT_EQ(*resp->getPublicKey(), *moResp->getPublicKey());
    shared_ptr<MslObject> moKeydata = moResp->getKeydata(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moKeydata);
    EXPECT_EQ(*keydata, *moKeydata);
}

TEST_F(DhResponseDataTest, mslObject)
{
    shared_ptr<ResponseData> resp = make_shared<ResponseData>(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, resp);
    EXPECT_EQ(KeyExchangeScheme::DIFFIE_HELLMAN.toString(), mo->getString(KEY_SCHEME));
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, mo->getMslObject(KEY_MASTER_TOKEN, encoder));
    EXPECT_EQ(*MASTER_TOKEN, *masterToken);
    shared_ptr<MslObject> keydata = mo->getMslObject(KEY_KEYDATA, encoder);
    EXPECT_EQ(PARAMETERS_ID, keydata->getString(KEY_PARAMETERS_ID));
    EXPECT_EQ(prependNullByte(*RESPONSE_PUBLIC_KEY), *keydata->getBytes(KEY_PUBLIC_KEY));
}

TEST_F(DhResponseDataTest, create)
{
    shared_ptr<ResponseData> data = make_shared<ResponseData>(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, data);
    shared_ptr<KeyResponseData> keyResponseData = KeyResponseData::create(ctx, mo);
    EXPECT_TRUE(keyResponseData);
    EXPECT_TRUE(instanceof<ResponseData>(keyResponseData));

    shared_ptr<ResponseData> moData = dynamic_pointer_cast<ResponseData>(keyResponseData);
    EXPECT_EQ(data->getKeyExchangeScheme(), moData->getKeyExchangeScheme());
    EXPECT_EQ(*data->getMasterToken(), *moData->getMasterToken());
    EXPECT_EQ(data->getParametersId(), moData->getParametersId());
    EXPECT_EQ(*data->getPublicKey(), *moData->getPublicKey());
}

TEST_F(DhResponseDataTest, missingParametersId)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<ResponseData> resp = make_shared<ResponseData>(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
    shared_ptr<MslObject> keydata = resp->getKeydata(encoder, ENCODER_FORMAT);

    EXPECT_FALSE(keydata->remove(KEY_PARAMETERS_ID).isNull());

    try {
        new ResponseData(MASTER_TOKEN, keydata);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(DhResponseDataTest, missingPublicKey)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<ResponseData> resp = make_shared<ResponseData>(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
    shared_ptr<MslObject> keydata = resp->getKeydata(encoder, ENCODER_FORMAT);

    EXPECT_FALSE(keydata->remove(KEY_PUBLIC_KEY).isNull());

    try {
        new ResponseData(MASTER_TOKEN, keydata);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(DhResponseDataTest, invalidPublicKey)
{
//    thrown.expect(MslKeyExchangeException.class);
//    thrown.expectMslError(MslError.KEYX_INVALID_PUBLIC_KEY);

    shared_ptr<ResponseData> resp = make_shared<ResponseData>(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
    shared_ptr<MslObject> keydata = resp->getKeydata(encoder, ENCODER_FORMAT);

    keydata->put(KEY_PUBLIC_KEY, make_shared<ByteArray>());

    try {
        new ResponseData(MASTER_TOKEN, keydata);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslKeyExchangeException& e) {
        EXPECT_EQ(MslError::KEYX_INVALID_PUBLIC_KEY, e.getError());
    }
}

TEST_F(DhResponseDataTest, equalsMasterToken)
{
    shared_ptr<MasterToken> masterTokenA = MslTestUtils::getMasterToken(ctx, 1, 1);
    shared_ptr<MasterToken> masterTokenB = MslTestUtils::getMasterToken(ctx, 1, 2);
    shared_ptr<ResponseData> dataA = make_shared<ResponseData>(masterTokenA, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
    shared_ptr<ResponseData> dataB = make_shared<ResponseData>(masterTokenB, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
    shared_ptr<ResponseData> dataA2 = make_shared<ResponseData>(masterTokenA, dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    EXPECT_TRUE(dataA->equals(dataA2));
    EXPECT_TRUE(dataA2->equals(dataA));
}

TEST_F(DhResponseDataTest, equalsParametersId)
{
    shared_ptr<ResponseData> dataA = make_shared<ResponseData>(MASTER_TOKEN, PARAMETERS_ID + "A", RESPONSE_PUBLIC_KEY);
    shared_ptr<ResponseData> dataB = make_shared<ResponseData>(MASTER_TOKEN, PARAMETERS_ID + "B", RESPONSE_PUBLIC_KEY);
    shared_ptr<ResponseData> dataA2 = make_shared<ResponseData>(MASTER_TOKEN, dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    EXPECT_TRUE(dataA->equals(dataA2));
    EXPECT_TRUE(dataA2->equals(dataA));
}

TEST_F(DhResponseDataTest, equalsPublicKey)
{
    shared_ptr<ResponseData> dataA = make_shared<ResponseData>(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
    shared_ptr<ResponseData> dataB = make_shared<ResponseData>(MASTER_TOKEN, PARAMETERS_ID, REQUEST_PUBLIC_KEY);
    shared_ptr<ResponseData> dataA2 = make_shared<ResponseData>(MASTER_TOKEN, dataA->getKeydata(encoder, ENCODER_FORMAT));

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
 * Fake key request data for the Diffie-Hellman key exchange scheme.
 */
struct FakeKeyRequestData : public KeyRequestData
{
    /** Create a new fake key request data. */
    FakeKeyRequestData() : KeyRequestData(KeyExchangeScheme::DIFFIE_HELLMAN) {}

    /** @inheritDoc */
    virtual shared_ptr<MslObject> getKeydata(std::shared_ptr<io::MslEncoderFactory>, const io::MslEncoderFormat&) const
    {
        return shared_ptr<MslObject>();
    }
};

/**
 * Fake key response data for the Diffie-Hellman key exchange scheme.
 */
struct FakeKeyResponseData : public KeyResponseData
{
    /** Create a new fake key response data. */
    FakeKeyResponseData() : KeyResponseData(shared_ptr<MasterToken>(), KeyExchangeScheme::DIFFIE_HELLMAN) {}

    /** @inheritDoc */
    virtual shared_ptr<MslObject> getKeydata(std::shared_ptr<io::MslEncoderFactory>, const io::MslEncoderFormat&) const
    {
        return shared_ptr<MslObject>();
    }
};

/** Key exchange factory unit tests. */
class DiffieHellmanExchangeTest : public ::testing::Test, public BaseTest
{
public:
    DiffieHellmanExchangeTest()
    : authutils(make_shared<MockAuthenticationUtils>())
    , factory(make_shared<DiffieHellmanExchange>(MockDiffieHellmanParameters::getDefaultParameters(), authutils))
    , entityAuthData(make_shared<PresharedAuthenticationData>(MockPresharedAuthenticationFactory::PSK_ESN))
    {
    }
    ~DiffieHellmanExchangeTest()
    {
        authutils->reset();
        ctx->getMslStore()->clearCryptoContexts();
        ctx->getMslStore()->clearServiceTokens();
    }
protected:
    /** Authentication utilities. */
    shared_ptr<MockAuthenticationUtils> authutils;
    /** Key exchange factory-> */
    shared_ptr<KeyExchangeFactory> factory;
    /** Entity authentication data. */
    shared_ptr<EntityAuthenticationData> entityAuthData;
};

TEST_F(DiffieHellmanExchangeTest, factory)
{
    EXPECT_EQ(KeyExchangeScheme::DIFFIE_HELLMAN, factory->getScheme());
}

TEST_F(DiffieHellmanExchangeTest, generateInitialResponse)
{
    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
    EXPECT_TRUE(keyxData);
    EXPECT_TRUE(keyxData->cryptoContext);
    EXPECT_TRUE(keyxData->keyResponseData);

    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    EXPECT_EQ(KeyExchangeScheme::DIFFIE_HELLMAN, keyResponseData->getKeyExchangeScheme());
    shared_ptr<MasterToken> masterToken = keyResponseData->getMasterToken();
    EXPECT_TRUE(masterToken);
    EXPECT_EQ(MockPresharedAuthenticationFactory::PSK_ESN, masterToken->getIdentity());
}

TEST_F(DiffieHellmanExchangeTest, wrongRequestInitialResponse)
{
//@Test(expected = MslInternalException.class)
    shared_ptr<KeyRequestData> keyRequestData = make_shared<FakeKeyRequestData>();
    EXPECT_THROW(factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData), MslInternalException);
}

TEST_F(DiffieHellmanExchangeTest, invalidParametersIdInitialResponse)
{
//    thrown.expect(MslKeyExchangeException.class);
//    thrown.expectMslError(MslError.UNKNOWN_KEYX_PARAMETERS_ID);

    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>("x", REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    try {
        factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslKeyExchangeException& e) {
        EXPECT_EQ(MslError::UNKNOWN_KEYX_PARAMETERS_ID, e.getError());
    }
}

TEST_F(DiffieHellmanExchangeTest, unknownParametersIdInitialResponse)
{
//    thrown.expect(MslKeyExchangeException.class);
//    thrown.expectMslError(MslError.UNKNOWN_KEYX_PARAMETERS_ID);

    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>("98765", REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    try {
        factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslKeyExchangeException& e) {
        EXPECT_EQ(MslError::UNKNOWN_KEYX_PARAMETERS_ID, e.getError());
    }
}

TEST_F(DiffieHellmanExchangeTest, generateSubsequentResponse)
{
    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN);
    EXPECT_TRUE(keyxData);
    EXPECT_TRUE(keyxData->cryptoContext);
    EXPECT_TRUE(keyxData->keyResponseData);

    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    EXPECT_EQ(KeyExchangeScheme::DIFFIE_HELLMAN, keyResponseData->getKeyExchangeScheme());
    shared_ptr<MasterToken> masterToken = keyResponseData->getMasterToken();
    EXPECT_TRUE(masterToken);
    EXPECT_EQ(MASTER_TOKEN->getIdentity(), masterToken->getIdentity());
    EXPECT_EQ(MASTER_TOKEN->getSerialNumber(), masterToken->getSerialNumber());
    EXPECT_EQ(MASTER_TOKEN->getSequenceNumber() + 1, masterToken->getSequenceNumber());
}

TEST_F(DiffieHellmanExchangeTest, untrustedMasterTokenSubsequentResponse)
{
//    thrown.expect(MslMasterTokenException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_UNTRUSTED);

    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    shared_ptr<MasterToken> masterToken = MslTestUtils::getUntrustedMasterToken(ctx);
    try {
        factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, masterToken);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslMasterTokenException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_UNTRUSTED, e.getError());
    }
}

TEST_F(DiffieHellmanExchangeTest, wrongRequestSubsequentResponse)
{
//@Test(expected = MslInternalException.class)
    shared_ptr<KeyRequestData> keyRequestData = make_shared<FakeKeyRequestData>();
    EXPECT_THROW(factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN), MslInternalException);
}

TEST_F(DiffieHellmanExchangeTest, invalidParametersIdSubsequentResponse)
{
//    thrown.expect(MslKeyExchangeException.class);
//    thrown.expectMslError(MslError.UNKNOWN_KEYX_PARAMETERS_ID);

    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>("x", REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    try {
        factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslKeyExchangeException& e) {
        EXPECT_EQ(MslError::UNKNOWN_KEYX_PARAMETERS_ID, e.getError());
    }
}

TEST_F(DiffieHellmanExchangeTest, unknownParametersIdSubsequentResponse)
{
//    thrown.expect(MslKeyExchangeException.class);
//    thrown.expectMslError(MslError.UNKNOWN_KEYX_PARAMETERS_ID);

    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>("98765", REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    try {
        factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslKeyExchangeException& e) {
        EXPECT_EQ(MslError::UNKNOWN_KEYX_PARAMETERS_ID, e.getError());
    }
}

TEST_F(DiffieHellmanExchangeTest, getCryptoContext)
{
    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
    shared_ptr<ICryptoContext> requestCryptoContext = keyxData->cryptoContext;
    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    shared_ptr<ICryptoContext> responseCryptoContext = factory->getCryptoContext(ctx, keyRequestData, keyResponseData, shared_ptr<MasterToken>());
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
    EXPECT_TRUE(requestPlaintext);
    EXPECT_EQ(*data, *requestPlaintext);
    EXPECT_EQ(*requestPlaintext, *responsePlaintext);

    // Verification should always succeed.
    EXPECT_TRUE(requestCryptoContext->verify(data, responseSignature, encoder));
    EXPECT_TRUE(responseCryptoContext->verify(data, requestSignature, encoder));
}

TEST_F(DiffieHellmanExchangeTest, wrongRequestCryptoContext)
{
//@Test(expected = MslInternalException.class)
    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;

    shared_ptr<KeyRequestData> fakeKeyRequestData = make_shared<FakeKeyRequestData>();
    EXPECT_THROW(factory->getCryptoContext(ctx, fakeKeyRequestData, keyResponseData, shared_ptr<MasterToken>()), MslInternalException);
}

TEST_F(DiffieHellmanExchangeTest, wrongResponseCryptoContext)
{
//@Test(expected = MslInternalException.class)
    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    shared_ptr<KeyResponseData> fakeKeyResponseData = make_shared<FakeKeyResponseData>();
    EXPECT_THROW(factory->getCryptoContext(ctx, keyRequestData, fakeKeyResponseData, shared_ptr<MasterToken>()), MslInternalException);
}

TEST_F(DiffieHellmanExchangeTest, parametersIdMismatchCryptoContext)
{
//    thrown.expect(MslKeyExchangeException.class);
//    thrown.expectMslError(MslError.KEYX_RESPONSE_REQUEST_MISMATCH);

    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    shared_ptr<MasterToken> masterToken = keyResponseData->getMasterToken();

    shared_ptr<KeyResponseData> mismatchedKeyResponseData = make_shared<ResponseData>(masterToken, PARAMETERS_ID + "x", RESPONSE_PUBLIC_KEY);

    try {
        factory->getCryptoContext(ctx, keyRequestData, mismatchedKeyResponseData, shared_ptr<MasterToken>());
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslKeyExchangeException& e) {
        EXPECT_EQ(MslError::KEYX_RESPONSE_REQUEST_MISMATCH, e.getError());
    }
}

TEST_F(DiffieHellmanExchangeTest, privateKeyMissingCryptoContext)
{
//    thrown.expect(MslKeyExchangeException.class);
//    thrown.expectMslError(MslError.KEYX_PRIVATE_KEY_MISSING);

    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(PARAMETERS_ID, REQUEST_PUBLIC_KEY, shared_ptr<PrivateKey>());
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyxData = factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;

    try {
        factory->getCryptoContext(ctx, keyRequestData, keyResponseData, shared_ptr<MasterToken>());
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslKeyExchangeException& e) {
        EXPECT_EQ(MslError::KEYX_PRIVATE_KEY_MISSING, e.getError());
    }
}

} //namespace anonymous

}}} // namespace netflix::msl::keyx
