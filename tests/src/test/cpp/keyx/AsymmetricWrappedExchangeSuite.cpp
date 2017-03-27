/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
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
#include <io/MslEncoderUtils.h>
#include <keyx/KeyExchangeFactory.h>
#include <keyx/KeyExchangeScheme.h>
#include <keyx/KeyRequestData.h>
#include <keyx/AsymmetricWrappedExchange.h>
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
#include <utility>

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

using RequestData = AsymmetricWrappedExchange::RequestData;
using ResponseData = AsymmetricWrappedExchange::ResponseData;
using KeyExchangeData = KeyExchangeFactory::KeyExchangeData;

/**
 * Asymmetric wrapped key exchange unit tests.
 */

namespace {

/** Key key exchange scheme. */
const string KEY_SCHEME = "scheme";
/** Key key request data. */
const string KEY_KEYDATA = "keydata";

/** Key key pair ID. */
const string KEY_KEY_PAIR_ID = "keypairid";
/** Key encrypted encryption key. */
const string KEY_ENCRYPTION_KEY = "encryptionkey";
/** Key encrypted HMAC key. */
const string KEY_HMAC_KEY = "hmackey";

const string KEYPAIR_ID = "keypairId";

/** Key mechanism. */
const string KEY_MECHANISM = "mechanism";
/** Key public key. */
const string KEY_PUBLIC_KEY = "publickey";

// This class ensures stuff shared between suites is only created once, since
// RSA stuff can be expensive to create.
class TestSingleton
{
public:
    static shared_ptr<MockMslContext> getMockMslContext() {
        static shared_ptr<MockMslContext> theInstance;
        if (!theInstance)
            theInstance = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
        return theInstance;
    }
    static shared_ptr<PublicKey> getPublicKey() { return keyInstance().first; }
    static shared_ptr<PrivateKey> getPrivateKey() { return keyInstance().second; }
private:
    static pair<shared_ptr<PublicKey>,shared_ptr<PrivateKey>> keyInstance() {
        static pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>> theInstance;
        if (!theInstance.first) {
            pair<PublicKey,PrivateKey> keypair = MslTestUtils::generateRsaKeys("RSA", 2048);
            theInstance = make_pair(make_shared<PublicKey>(keypair.first), make_shared<PrivateKey>(keypair.second));
        }
        return theInstance;
    }
};

// This class holds the stuff common to the suites in this file.
class BaseTest
{
public:
    BaseTest()
    : ctx(TestSingleton::getMockMslContext())
    , ENCODER_FORMAT(MslEncoderFormat::JSON)
    , encoder(ctx->getMslEncoderFactory())
    , MASTER_TOKEN(MslTestUtils::getMasterToken(ctx, 1, 1))
    , ENCRYPTION_KEY(MASTER_TOKEN->getEncryptionKey().getEncoded())
    , HMAC_KEY(MASTER_TOKEN->getSignatureKey().getEncoded())
    , RSA_PUBLIC_KEY(TestSingleton::getPublicKey())
    , RSA_PRIVATE_KEY(TestSingleton::getPrivateKey())
    , IDENTITY(MockPresharedAuthenticationFactory::PSK_ESN)
    {
    }
protected:
    virtual ~BaseTest() {}
    /** MSL context. */
    shared_ptr<MslContext> ctx;
    /** MSL encoder format. */
    const MslEncoderFormat ENCODER_FORMAT;
    /** MSL encoder factory */
    shared_ptr<MslEncoderFactory> encoder;

    shared_ptr<MasterToken> MASTER_TOKEN;
    shared_ptr<ByteArray> ENCRYPTION_KEY;
    shared_ptr<ByteArray> HMAC_KEY;
    shared_ptr<PublicKey> RSA_PUBLIC_KEY;
    shared_ptr<PrivateKey> RSA_PRIVATE_KEY;

    const string IDENTITY;
};

struct TestParameters
{
    const RequestData::Mechanism mechanism;
    shared_ptr<PublicKey> publicKey;
    shared_ptr<PrivateKey> privateKey;
    TestParameters(const RequestData::Mechanism& m, shared_ptr<PublicKey> pubk, shared_ptr<PrivateKey> privk)
        : mechanism(m), publicKey(pubk), privateKey(privk) {}
    friend ostream & operator<<(ostream &os, const TestParameters& tp);
};
ostream & operator<<(ostream& os, const TestParameters& tp) {
    return os << "mechanism:" << tp.mechanism.toString();
}
string sufx(testing::TestParamInfo<struct TestParameters> tpi) {
    return tpi.param.mechanism.toString();
}

}  // namespace anonymous

/** Request data unit tests. */

class RequestDataTest : public ::testing::TestWithParam<TestParameters>, protected BaseTest
{
};

INSTANTIATE_TEST_CASE_P(AsymmetricWrappedExchange, RequestDataTest,
    ::testing::Values(
            TestParameters(RequestData::Mechanism::RSA,       TestSingleton::getPublicKey(), TestSingleton::getPrivateKey()),
            TestParameters(RequestData::Mechanism::JWE_RSA,   TestSingleton::getPublicKey(), TestSingleton::getPrivateKey()),
            TestParameters(RequestData::Mechanism::JWEJS_RSA, TestSingleton::getPublicKey(), TestSingleton::getPrivateKey()),
            TestParameters(RequestData::Mechanism::JWK_RSA,   TestSingleton::getPublicKey(), TestSingleton::getPrivateKey()),
            TestParameters(RequestData::Mechanism::JWK_RSAES, TestSingleton::getPublicKey(), TestSingleton::getPrivateKey())
    ), &sufx);

TEST_P(RequestDataTest, ctors)
{
    const RequestData req(KEYPAIR_ID, GetParam().mechanism, GetParam().publicKey, GetParam().privateKey);
    EXPECT_EQ(KeyExchangeScheme::ASYMMETRIC_WRAPPED, req.getKeyExchangeScheme());
    EXPECT_EQ(KEYPAIR_ID, req.getKeyPairId());
    EXPECT_EQ(GetParam().mechanism, req.getMechanism());
    EXPECT_EQ(*GetParam().privateKey->getEncoded(), *req.getPrivateKey()->getEncoded());
    EXPECT_EQ(*GetParam().publicKey->getEncoded(), *req.getPublicKey()->getEncoded());
    shared_ptr<MslObject> keydata = req.getKeydata(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(keydata);

    const RequestData moReq(keydata);
    EXPECT_EQ(req.getKeyExchangeScheme(), moReq.getKeyExchangeScheme());
    EXPECT_EQ(req.getKeyPairId(), moReq.getKeyPairId());
    EXPECT_EQ(req.getMechanism(), moReq.getMechanism());
    EXPECT_FALSE(moReq.getPrivateKey());
    EXPECT_EQ(*req.getPublicKey()->getEncoded(), *moReq.getPublicKey()->getEncoded());
    shared_ptr<MslObject> moKeydata = moReq.getKeydata(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moKeydata);
    EXPECT_TRUE(MslEncoderUtils::equalObjects(keydata, moKeydata));
}

TEST_P(RequestDataTest, mslObject)
{
    shared_ptr<RequestData> req = make_shared<RequestData>(KEYPAIR_ID, GetParam().mechanism, GetParam().publicKey, GetParam().privateKey);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, req);
    EXPECT_EQ(KeyExchangeScheme::ASYMMETRIC_WRAPPED.toString(), mo->getString(KEY_SCHEME));
    shared_ptr<MslObject> keydata = mo->getMslObject(KEY_KEYDATA, encoder);
    EXPECT_EQ(KEYPAIR_ID, keydata->getString(KEY_KEY_PAIR_ID));
    EXPECT_EQ(GetParam().mechanism.toString(), keydata->getString(KEY_MECHANISM));
    EXPECT_EQ(*GetParam().publicKey->getEncoded(), *keydata->getBytes(KEY_PUBLIC_KEY));
}


TEST_P(RequestDataTest, create)
{
    shared_ptr<RequestData> data = make_shared<RequestData>(KEYPAIR_ID, GetParam().mechanism, GetParam().publicKey, GetParam().privateKey);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, data);
    shared_ptr<KeyRequestData> keyRequestData = KeyRequestData::create(ctx, mo);
    EXPECT_TRUE(keyRequestData);
    EXPECT_TRUE(instanceof<RequestData>(keyRequestData));

    shared_ptr<RequestData> moData = dynamic_pointer_cast<RequestData>(keyRequestData);
    EXPECT_EQ(data->getKeyExchangeScheme(), moData->getKeyExchangeScheme());
    EXPECT_EQ(data->getKeyPairId(), moData->getKeyPairId());
    EXPECT_EQ(data->getMechanism(), moData->getMechanism());
    EXPECT_FALSE(moData->getPrivateKey());
    EXPECT_EQ(*data->getPublicKey()->getEncoded(), *moData->getPublicKey()->getEncoded());
}

TEST_P(RequestDataTest, missingKeypairId)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    const RequestData req(KEYPAIR_ID, GetParam().mechanism, GetParam().publicKey, GetParam().privateKey);
    shared_ptr<MslObject> keydata = req.getKeydata(encoder, ENCODER_FORMAT);

    EXPECT_FALSE(keydata->remove(KEY_KEY_PAIR_ID).isNull());

    try {
        RequestData requestData(keydata);
        ADD_FAILURE() << "Should have thrown";
    } catch(const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_P(RequestDataTest, missingMechanism)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    const RequestData req(KEYPAIR_ID, GetParam().mechanism, GetParam().publicKey, GetParam().privateKey);
    shared_ptr<MslObject> keydata = req.getKeydata(encoder, ENCODER_FORMAT);

    EXPECT_FALSE(keydata->remove(KEY_MECHANISM).isNull());

    try {
        RequestData requestData(keydata);
        ADD_FAILURE() << "Should have thrown";
    } catch(const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_P(RequestDataTest, invalidMechanism)
{
//    thrown.expect(MslKeyExchangeException.class);
//    thrown.expectMslError(MslError.UNIDENTIFIED_KEYX_MECHANISM);

    const RequestData req(KEYPAIR_ID, GetParam().mechanism, GetParam().publicKey, GetParam().privateKey);
    shared_ptr<MslObject> keydata = req.getKeydata(encoder, ENCODER_FORMAT);

    keydata->put<string>(KEY_MECHANISM, "x");

    try {
        RequestData requestData(keydata);
        ADD_FAILURE() << "Should have thrown";
    } catch(const MslKeyExchangeException& e) {
        EXPECT_EQ(MslError::UNIDENTIFIED_KEYX_MECHANISM, e.getError());
    }
}

TEST_P(RequestDataTest, missingPublicKey)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    const RequestData req(KEYPAIR_ID, GetParam().mechanism, GetParam().publicKey, GetParam().privateKey);
    shared_ptr<MslObject> keydata = req.getKeydata(encoder, ENCODER_FORMAT);

    EXPECT_FALSE(keydata->remove(KEY_PUBLIC_KEY).isNull());

    try {
        RequestData requestData(keydata);
        ADD_FAILURE() << "Should have thrown";
    } catch(const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_P(RequestDataTest, invalidPublicKey)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError.INVALID_PUBLIC_KEY);

    const RequestData req(KEYPAIR_ID, GetParam().mechanism, GetParam().publicKey, GetParam().privateKey);
    shared_ptr<MslObject> keydata = req.getKeydata(encoder, ENCODER_FORMAT);

    shared_ptr<ByteArray> encodedKey = GetParam().publicKey->getEncoded();
    shared_ptr<ByteArray> shortKey = make_shared<ByteArray>();
    keydata->put(KEY_PUBLIC_KEY, shortKey);

    try {
        RequestData requestData(keydata);
        ADD_FAILURE() << "Should have thrown";
    } catch(const MslCryptoException& e) {
        EXPECT_EQ(MslError::INVALID_PUBLIC_KEY, e.getError());
    }
}

TEST_P(RequestDataTest, equalsKeyPairId)
{
    shared_ptr<RequestData> dataA  = make_shared<RequestData>(KEYPAIR_ID + "A", AsymmetricWrappedExchange::RequestData::Mechanism::JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
    shared_ptr<RequestData> dataB  = make_shared<RequestData>(KEYPAIR_ID + "B", AsymmetricWrappedExchange::RequestData::Mechanism::JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
    shared_ptr<RequestData> dataA2 = make_shared<RequestData>(dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    // The private keys don't transfer via the parse constructor.
    EXPECT_FALSE(dataA->equals(dataA2));
    EXPECT_FALSE(dataA2->equals(dataA));
}

TEST_P(RequestDataTest, operatorEqualsKeyPairId)
{
    shared_ptr<RequestData> dataA  = make_shared<RequestData>(KEYPAIR_ID + "A", AsymmetricWrappedExchange::RequestData::Mechanism::JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
    shared_ptr<RequestData> dataB  = make_shared<RequestData>(KEYPAIR_ID + "B", AsymmetricWrappedExchange::RequestData::Mechanism::JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
    shared_ptr<RequestData> dataA2 = make_shared<RequestData>(dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(*dataA == *dataA);

    EXPECT_FALSE(*dataA == *dataB);
    EXPECT_FALSE(*dataB == *dataA);

    // The private keys don't transfer via the parse constructor.
    EXPECT_FALSE(*dataA == *dataA2);
    EXPECT_FALSE(*dataA2 == *dataA);
}

TEST_P(RequestDataTest, equalsMechanism)
{
    shared_ptr<RequestData> dataA  = make_shared<RequestData>(KEYPAIR_ID, AsymmetricWrappedExchange::RequestData::Mechanism::JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
    shared_ptr<RequestData> dataB  = make_shared<RequestData>(KEYPAIR_ID, AsymmetricWrappedExchange::RequestData::Mechanism::ECC, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
    shared_ptr<RequestData> dataA2 = make_shared<RequestData>(dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    // The private keys don't transfer via the parse constructor.
    EXPECT_FALSE(dataA->equals(dataA2));
    EXPECT_FALSE(dataA2->equals(dataA));
}

TEST_P(RequestDataTest, equalsPublicKey)
{
    pair<PublicKey,PrivateKey> otherkeyPair = MslTestUtils::generateRsaKeys("RSA", 512);
    shared_ptr<PublicKey> otherPublicKey = make_shared<PublicKey>(otherkeyPair.first);
    shared_ptr<RequestData> dataA  = make_shared<RequestData>(KEYPAIR_ID, AsymmetricWrappedExchange::RequestData::Mechanism::JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
    shared_ptr<RequestData> dataB  = make_shared<RequestData>(KEYPAIR_ID, AsymmetricWrappedExchange::RequestData::Mechanism::JWE_RSA, otherPublicKey, RSA_PRIVATE_KEY);
    shared_ptr<RequestData> dataA2 = make_shared<RequestData>(dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    // The private keys don't transfer via the parse constructor.
    EXPECT_FALSE(dataA->equals(dataA2));
    EXPECT_FALSE(dataA2->equals(dataA));
}

TEST_P(RequestDataTest, equalsPrivateKey)
{
    pair<PublicKey,PrivateKey> otherkeyPair = MslTestUtils::generateRsaKeys("RSA", 512);
    shared_ptr<PrivateKey> otherPrivateKey = make_shared<PrivateKey>(otherkeyPair.second);
    shared_ptr<RequestData> dataA  = make_shared<RequestData>(KEYPAIR_ID, AsymmetricWrappedExchange::RequestData::Mechanism::JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
    shared_ptr<RequestData> dataB  = make_shared<RequestData>(KEYPAIR_ID, AsymmetricWrappedExchange::RequestData::Mechanism::JWE_RSA, RSA_PUBLIC_KEY, otherPrivateKey);
    shared_ptr<RequestData> dataA2 = make_shared<RequestData>(dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    // The private keys don't transfer via the parse constructor.
    EXPECT_FALSE(dataA->equals(dataA2));
    EXPECT_FALSE(dataA2->equals(dataA));
}

TEST_P(RequestDataTest, equalsObject)
{
    shared_ptr<RequestData> data = make_shared<RequestData>(KEYPAIR_ID, AsymmetricWrappedExchange::RequestData::Mechanism::JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
    EXPECT_FALSE(data->equals(shared_ptr<RequestData>()));
}

/** Response data unit tests. */

class AsymmetricWrappedExchange_ResponseDataTest : public ::testing::Test, protected BaseTest
{
public:
    const string KEY_MASTER_TOKEN = "mastertoken";
};

TEST_F(AsymmetricWrappedExchange_ResponseDataTest, ctors)
{
    const ResponseData resp(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
    EXPECT_EQ(*ENCRYPTION_KEY, *resp.getEncryptionKey());
    EXPECT_EQ(*HMAC_KEY, *resp.getHmacKey());
    EXPECT_EQ(KeyExchangeScheme::ASYMMETRIC_WRAPPED, resp.getKeyExchangeScheme());
    EXPECT_EQ(KEYPAIR_ID, resp.getKeyPairId());
    EXPECT_EQ(MASTER_TOKEN, resp.getMasterToken());
    shared_ptr<MslObject> keydata = resp.getKeydata(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(keydata);

    const ResponseData moResp(MASTER_TOKEN, keydata);
    EXPECT_EQ(*resp.getEncryptionKey(), *moResp.getEncryptionKey());
    EXPECT_EQ(*resp.getHmacKey(), *moResp.getHmacKey());
    EXPECT_EQ(resp.getKeyExchangeScheme(), moResp.getKeyExchangeScheme());
    EXPECT_EQ(resp.getKeyPairId(), moResp.getKeyPairId());
    EXPECT_EQ(*resp.getMasterToken(), *moResp.getMasterToken());
    shared_ptr<MslObject> moKeydata = moResp.getKeydata(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moKeydata);
    EXPECT_TRUE(MslEncoderUtils::equalObjects(keydata, moKeydata));
}

TEST_F(AsymmetricWrappedExchange_ResponseDataTest, mslObject)
{
    shared_ptr<ResponseData> resp = make_shared<ResponseData>(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, resp);
    EXPECT_EQ(KeyExchangeScheme::ASYMMETRIC_WRAPPED.toString(), mo->getString(KEY_SCHEME));
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, mo->getMslObject(KEY_MASTER_TOKEN, encoder));
    EXPECT_EQ(*MASTER_TOKEN, *masterToken);
    shared_ptr<MslObject> keydata = mo->getMslObject(KEY_KEYDATA, encoder);
    EXPECT_EQ(KEYPAIR_ID, keydata->getString(KEY_KEY_PAIR_ID));
    EXPECT_EQ(*ENCRYPTION_KEY, *keydata->getBytes(KEY_ENCRYPTION_KEY));
    EXPECT_EQ(*HMAC_KEY, *keydata->getBytes(KEY_HMAC_KEY));
}

TEST_F(AsymmetricWrappedExchange_ResponseDataTest, create)
{
    shared_ptr<ResponseData> data = make_shared<ResponseData>(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, data);
    shared_ptr<KeyResponseData> keyResponseData = KeyResponseData::create(ctx, mo);
    EXPECT_TRUE(keyResponseData);
    EXPECT_TRUE(instanceof<ResponseData>(keyResponseData));

    shared_ptr<ResponseData> moData = dynamic_pointer_cast<ResponseData>(keyResponseData);
    EXPECT_EQ(*data->getEncryptionKey(), *moData->getEncryptionKey());
    EXPECT_EQ(*data->getHmacKey(), *moData->getHmacKey());
    EXPECT_EQ(data->getKeyExchangeScheme(), moData->getKeyExchangeScheme());
    EXPECT_EQ(data->getKeyPairId(), moData->getKeyPairId());
    EXPECT_EQ(*data->getMasterToken(), *moData->getMasterToken());
}

TEST_F(AsymmetricWrappedExchange_ResponseDataTest, missingKeyPairId)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    const ResponseData resp(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<MslObject> keydata = resp.getKeydata(encoder, ENCODER_FORMAT);

    EXPECT_FALSE(keydata->remove(KEY_KEY_PAIR_ID).isNull());

    try {
        ResponseData responseData(MASTER_TOKEN, keydata);
        ADD_FAILURE() << "Should have thrown";
    } catch(const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(AsymmetricWrappedExchange_ResponseDataTest, missingEncryptionKey)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    const ResponseData resp(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<MslObject> keydata = resp.getKeydata(encoder, ENCODER_FORMAT);

    EXPECT_FALSE(keydata->remove(KEY_ENCRYPTION_KEY).isNull());

    try {
        ResponseData responseData(MASTER_TOKEN, keydata);
        ADD_FAILURE() << "Should have thrown";
    } catch(const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(AsymmetricWrappedExchange_ResponseDataTest, missingHmacKey)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    const ResponseData resp(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<MslObject> keydata = resp.getKeydata(encoder, ENCODER_FORMAT);

    EXPECT_FALSE(keydata->remove(KEY_HMAC_KEY).isNull());

    try {
        ResponseData responseData(MASTER_TOKEN, keydata);
        ADD_FAILURE() << "Should have thrown";
    } catch(const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(AsymmetricWrappedExchange_ResponseDataTest, equalsMasterToken)
{
    shared_ptr<MasterToken>masterTokenA = MslTestUtils::getMasterToken(ctx, 1, 1);
    shared_ptr<MasterToken>masterTokenB = MslTestUtils::getMasterToken(ctx, 1, 2);
    shared_ptr<ResponseData> dataA = make_shared<ResponseData>(masterTokenA, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<ResponseData> dataB = make_shared<ResponseData>(masterTokenB, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<ResponseData> dataA2 = make_shared<ResponseData>(masterTokenA, dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    EXPECT_TRUE(dataA->equals(dataA2));
    EXPECT_TRUE(dataA2->equals(dataA));
}

TEST_F(AsymmetricWrappedExchange_ResponseDataTest, equalsKeyPairId)
{
    shared_ptr<ResponseData> dataA = make_shared<ResponseData>(MASTER_TOKEN, KEYPAIR_ID + "A", ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<ResponseData> dataB = make_shared<ResponseData>(MASTER_TOKEN, KEYPAIR_ID + "B", ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<ResponseData> dataA2 = make_shared<ResponseData>(MASTER_TOKEN, dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    EXPECT_TRUE(dataA->equals(dataA2));
    EXPECT_TRUE(dataA2->equals(dataA));
}

TEST_F(AsymmetricWrappedExchange_ResponseDataTest, operatorEqualsKeyPairId)
{
    shared_ptr<ResponseData> dataA = make_shared<ResponseData>(MASTER_TOKEN, KEYPAIR_ID + "A", ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<ResponseData> dataB = make_shared<ResponseData>(MASTER_TOKEN, KEYPAIR_ID + "B", ENCRYPTION_KEY, HMAC_KEY);
    shared_ptr<ResponseData> dataA2 = make_shared<ResponseData>(MASTER_TOKEN, dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(*dataA == *dataA);

    EXPECT_FALSE(*dataA == *dataB);
    EXPECT_FALSE(*dataB == *dataA);

    EXPECT_TRUE(*dataA == *dataA2);
    EXPECT_TRUE(*dataA2 == *dataA);
}

TEST_F(AsymmetricWrappedExchange_ResponseDataTest, equalsEncryptionKey)
{
    shared_ptr<ByteArray> encryptionKeyA = make_shared<ByteArray>(*ENCRYPTION_KEY);
    shared_ptr<ByteArray> encryptionKeyB = make_shared<ByteArray>(*ENCRYPTION_KEY);
    ++(*encryptionKeyB)[0];
    shared_ptr<ResponseData> dataA = make_shared<ResponseData>(MASTER_TOKEN, KEYPAIR_ID, encryptionKeyA, HMAC_KEY);
    shared_ptr<ResponseData> dataB = make_shared<ResponseData>(MASTER_TOKEN, KEYPAIR_ID, encryptionKeyB, HMAC_KEY);
    shared_ptr<ResponseData> dataA2 = make_shared<ResponseData>(MASTER_TOKEN, dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    EXPECT_TRUE(dataA->equals(dataA2));
    EXPECT_TRUE(dataA2->equals(dataA));
}

TEST_F(AsymmetricWrappedExchange_ResponseDataTest, equalsHmacKey)
{
    shared_ptr<ByteArray> hmacKeyA = make_shared<ByteArray>(*HMAC_KEY);
    shared_ptr<ByteArray> hmacKeyB = make_shared<ByteArray>(*HMAC_KEY);
    ++(*hmacKeyB)[0];
    shared_ptr<ResponseData> dataA = make_shared<ResponseData>(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, hmacKeyA);
    shared_ptr<ResponseData> dataB = make_shared<ResponseData>(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, hmacKeyB);
    shared_ptr<ResponseData> dataA2 = make_shared<ResponseData>(MASTER_TOKEN, dataA->getKeydata(encoder, ENCODER_FORMAT));

    EXPECT_TRUE(dataA->equals(dataA));

    EXPECT_FALSE(dataA->equals(dataB));
    EXPECT_FALSE(dataB->equals(dataA));

    EXPECT_TRUE(dataA->equals(dataA2));
    EXPECT_TRUE(dataA2->equals(dataA));
}

TEST_F(AsymmetricWrappedExchange_ResponseDataTest, equalsObject)
{
    shared_ptr<ResponseData> data = make_shared<ResponseData>(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
    EXPECT_FALSE(data->equals(shared_ptr<ResponseData>()));
}

/** Key exchange factory unit tests. */

class KeyExchangeFactoryTest : public ::testing::TestWithParam<TestParameters>, protected BaseTest
{
public:
    KeyExchangeFactoryTest()
    : authutils(make_shared<MockAuthenticationUtils>())
    , random(ctx->getRandom())
    , factory(make_shared<AsymmetricWrappedExchange>(authutils))
    , entityAuthData(make_shared<PresharedAuthenticationData>(IDENTITY))
    {}

protected:
    virtual void SetUp()
    {
        authutils.reset();
        ctx->getMslStore()->clearCryptoContexts();
        ctx->getMslStore()->clearServiceTokens();
    }

    /**
     * @param ctx MSL context.
     * @param encryptionKey master token encryption key.
     * @param hmacKey master token HMAC key.
     * @return a new master token.
     * @throws MslEncodingException if there is an error encoding the data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslException if the master token is constructed incorrectly.
     * @throws MslException if there is an error editing the data.
     * @throws MslEncoderException if there is an error modifying the data.
     */
    shared_ptr<MasterToken> getUntrustedMasterToken(shared_ptr<MslContext> ctx, const SecretKey& encryptionKey, const SecretKey& hmacKey)
    {
        shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() + 1000);
        shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 2000);
        const string identity = MockPresharedAuthenticationFactory::PSK_ESN;
        shared_ptr<MasterToken>masterToken = make_shared<MasterToken>(ctx, renewalWindow, expiration, 1L, 1L, shared_ptr<MslObject>(), identity, encryptionKey, hmacKey);
        shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, masterToken);
        shared_ptr<ByteArray> signature = mo->getBytes("signature");
        ++(*signature)[1];
        mo->put("signature", signature);
        shared_ptr<MasterToken> untrustedMasterToken = make_shared<MasterToken>(ctx, mo);
        return untrustedMasterToken;
    }

    /** Authentication utilities. */
    shared_ptr<MockAuthenticationUtils> authutils;
    /** Random. */
    shared_ptr<IRandom> random;
    /** Key exchange factory-> */
    shared_ptr<KeyExchangeFactory> factory;
    /** Entity authentication data */
    shared_ptr<EntityAuthenticationData> entityAuthData;
};

INSTANTIATE_TEST_CASE_P(AsymmetricWrappedExchange, KeyExchangeFactoryTest,
    ::testing::Values(
            TestParameters(RequestData::Mechanism::RSA,       TestSingleton::getPublicKey(), TestSingleton::getPrivateKey()),
//            TestParameters(RequestData::Mechanism::JWE_RSA,   TestSingleton::getPublicKey(), TestSingleton::getPrivateKey()),  FIXME TODO
//            TestParameters(RequestData::Mechanism::JWEJS_RSA, TestSingleton::getPublicKey(), TestSingleton::getPrivateKey()),  FIXME TODO
            TestParameters(RequestData::Mechanism::JWK_RSA,   TestSingleton::getPublicKey(), TestSingleton::getPrivateKey()),
            TestParameters(RequestData::Mechanism::JWK_RSAES, TestSingleton::getPublicKey(), TestSingleton::getPrivateKey())
    ), &sufx);


TEST_P(KeyExchangeFactoryTest, generateInitialResponse)
{
    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(KEYPAIR_ID, GetParam().mechanism, GetParam().publicKey, GetParam().privateKey);
    shared_ptr<KeyExchangeData> keyxData = factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
    EXPECT_TRUE(keyxData);
    EXPECT_TRUE(keyxData->cryptoContext);
    EXPECT_TRUE(keyxData->keyResponseData);

    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    EXPECT_EQ(KeyExchangeScheme::ASYMMETRIC_WRAPPED, keyResponseData->getKeyExchangeScheme());
    shared_ptr<MasterToken>masterToken = keyResponseData->getMasterToken();
    EXPECT_TRUE(masterToken);
    EXPECT_EQ(IDENTITY, masterToken->getIdentity());
}

TEST_P(KeyExchangeFactoryTest, generateSubsequentResponse)
{
    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(KEYPAIR_ID, GetParam().mechanism, GetParam().publicKey, GetParam().privateKey);
    shared_ptr<KeyExchangeData> keyxData = factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN);
    EXPECT_TRUE(keyxData);
    EXPECT_TRUE(keyxData->cryptoContext);
    EXPECT_TRUE(keyxData->keyResponseData);

    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    EXPECT_EQ(KeyExchangeScheme::ASYMMETRIC_WRAPPED, keyResponseData->getKeyExchangeScheme());
    shared_ptr<MasterToken>masterToken = keyResponseData->getMasterToken();
    EXPECT_TRUE(masterToken);
    EXPECT_EQ(MASTER_TOKEN->getIdentity(), masterToken->getIdentity());
    EXPECT_EQ(MASTER_TOKEN->getSerialNumber(), masterToken->getSerialNumber());
    EXPECT_EQ(MASTER_TOKEN->getSequenceNumber() + 1, masterToken->getSequenceNumber());
}

TEST_P(KeyExchangeFactoryTest, untrustedMasterTokenSubsequentResponse)
{
//    thrown.expect(MslMasterTokenException.class);

    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(KEYPAIR_ID, GetParam().mechanism, GetParam().publicKey, GetParam().privateKey);
    const SecretKey encryptionKey = MockPresharedAuthenticationFactory::KPE;
    const SecretKey hmacKey = MockPresharedAuthenticationFactory::KPH;
    shared_ptr<MasterToken>masterToken = getUntrustedMasterToken(ctx, encryptionKey, hmacKey);
    EXPECT_THROW(factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, masterToken), MslMasterTokenException);
}

TEST_P(KeyExchangeFactoryTest, getCryptoContext)
{
    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(KEYPAIR_ID, GetParam().mechanism, GetParam().publicKey, GetParam().privateKey);
    shared_ptr<KeyExchangeData> keyxData = factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
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

TEST_P(KeyExchangeFactoryTest, invalidWrappedEncryptionKeyCryptoContext)
{
//    thrown.expect(MslCryptoException.class);

    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(KEYPAIR_ID, GetParam().mechanism, GetParam().publicKey, GetParam().privateKey);
    shared_ptr<KeyExchangeData> keyxData = factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    shared_ptr<MasterToken>masterToken = keyResponseData->getMasterToken();

    shared_ptr<MslObject> keydata = keyResponseData->getKeydata(encoder, ENCODER_FORMAT);
    shared_ptr<ByteArray> wrappedEncryptionKey = keydata->getBytes(KEY_ENCRYPTION_KEY);
    // I think I have to change length - 2 because of padding.
    ++(*wrappedEncryptionKey)[wrappedEncryptionKey->size()-2];
    keydata->put(KEY_ENCRYPTION_KEY, wrappedEncryptionKey);
    shared_ptr<ByteArray> wrappedHmacKey = keydata->getBytes(KEY_HMAC_KEY);

    shared_ptr<KeyResponseData> invalidKeyResponseData = make_shared<ResponseData>(masterToken, KEYPAIR_ID, wrappedEncryptionKey, wrappedHmacKey);
    EXPECT_THROW(factory->getCryptoContext(ctx, keyRequestData, invalidKeyResponseData, shared_ptr<MasterToken>()), MslCryptoException);
}

TEST_P(KeyExchangeFactoryTest, invalidWrappedHmacKeyCryptoContext)
{
//    thrown.expect(MslCryptoException.class);

    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(KEYPAIR_ID, GetParam().mechanism, GetParam().publicKey, GetParam().privateKey);
    shared_ptr<KeyExchangeData> keyxData = factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    shared_ptr<MasterToken>masterToken = keyResponseData->getMasterToken();

    shared_ptr<MslObject> keydata = keyResponseData->getKeydata(encoder, ENCODER_FORMAT);
    shared_ptr<ByteArray> wrappedHmacKey = keydata->getBytes(KEY_HMAC_KEY);
    // I think I have to change length - 2 because of padding.
    ++(*wrappedHmacKey)[wrappedHmacKey->size()-2];
    keydata->put(KEY_HMAC_KEY, wrappedHmacKey);
    shared_ptr<ByteArray> wrappedEncryptionKey = keydata->getBytes(KEY_ENCRYPTION_KEY);

    shared_ptr<KeyResponseData> invalidKeyResponseData = make_shared<ResponseData>(masterToken, KEYPAIR_ID, wrappedEncryptionKey, wrappedHmacKey);
    EXPECT_THROW(factory->getCryptoContext(ctx, keyRequestData, invalidKeyResponseData, shared_ptr<MasterToken>()), MslCryptoException);
}

class AsymmetricWrappedExchange_KeyExchangeFactoryTest : public ::testing::Test, protected BaseTest
{
public:
    AsymmetricWrappedExchange_KeyExchangeFactoryTest()
    : authutils(make_shared<MockAuthenticationUtils>())
    , random(ctx->getRandom())
    , factory(make_shared<AsymmetricWrappedExchange>(authutils))
    , entityAuthData(make_shared<PresharedAuthenticationData>(IDENTITY))
    {}

protected:
    virtual void SetUp()
    {
        authutils.reset();
        ctx->getMslStore()->clearCryptoContexts();
        ctx->getMslStore()->clearServiceTokens();
    }

    /**
     * Fake key request data for the asymmetric wrapped key exchange scheme.
     */
    class FakeKeyRequestData : public KeyRequestData
    {
    public:
        FakeKeyRequestData() : KeyRequestData(KeyExchangeScheme::ASYMMETRIC_WRAPPED) {}
        virtual shared_ptr<MslObject> getKeydata(shared_ptr<io::MslEncoderFactory>, const MslEncoderFormat&) const {
            return shared_ptr<MslObject>();
        }
    };

    /**
     * Fake key response data for the asymmetric wrapped key exchange
     * scheme.
     */
    class FakeKeyResponseData : public KeyResponseData
    {
    public:
        FakeKeyResponseData(shared_ptr<MasterToken> mt) : KeyResponseData(mt, KeyExchangeScheme::ASYMMETRIC_WRAPPED) {}
        virtual shared_ptr<MslObject> getKeydata(shared_ptr<MslEncoderFactory>, const MslEncoderFormat&) const {
            return shared_ptr<MslObject>();
        }
    };

    /** Authentication utilities. */
    shared_ptr<MockAuthenticationUtils> authutils;
    /** Random. */
    shared_ptr<IRandom> random;
    /** Key exchange factory-> */
    shared_ptr<KeyExchangeFactory> factory;
    /** Entity authentication data */
    shared_ptr<EntityAuthenticationData> entityAuthData;
};

TEST_F(AsymmetricWrappedExchange_KeyExchangeFactoryTest, factory)
{
    EXPECT_EQ(KeyExchangeScheme::ASYMMETRIC_WRAPPED, factory->getScheme());
}

//@Test(expected = MslInternalException.class)
TEST_F(AsymmetricWrappedExchange_KeyExchangeFactoryTest, wrongRequestInitialResponse)
{
    shared_ptr<KeyRequestData> keyRequestData = make_shared<FakeKeyRequestData>();
    EXPECT_THROW(factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData), MslInternalException);
}

//@Test(expected = MslInternalException.class)
TEST_F(AsymmetricWrappedExchange_KeyExchangeFactoryTest, wrongRequestSubsequentResponse)
{
    shared_ptr<KeyRequestData> keyRequestData = make_shared<FakeKeyRequestData>();
    EXPECT_THROW(factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN), MslInternalException);
}

//@Test(expected = MslInternalException.class)
TEST_F(AsymmetricWrappedExchange_KeyExchangeFactoryTest, wrongRequestCryptoContext)
{
    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(KEYPAIR_ID, AsymmetricWrappedExchange::RequestData::Mechanism::JWK_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
    shared_ptr<KeyExchangeData> keyxData = factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;

    shared_ptr<KeyRequestData> fakeKeyRequestData = make_shared<FakeKeyRequestData>();
    EXPECT_THROW(factory->getCryptoContext(ctx, fakeKeyRequestData, keyResponseData, shared_ptr<MasterToken>()), MslInternalException);
}

//@Test(expected = MslInternalException.class)
TEST_F(AsymmetricWrappedExchange_KeyExchangeFactoryTest, wrongResponseCryptoContext)
{
    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(KEYPAIR_ID, AsymmetricWrappedExchange::RequestData::Mechanism::JWK_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
    shared_ptr<KeyResponseData> fakeKeyResponseData = make_shared<FakeKeyResponseData>(MASTER_TOKEN);
    EXPECT_THROW(factory->getCryptoContext(ctx, keyRequestData, fakeKeyResponseData, shared_ptr<MasterToken>()), MslInternalException);
}

TEST_F(AsymmetricWrappedExchange_KeyExchangeFactoryTest, keyIdMismatchCryptoContext)
{
//    thrown.expect(MslKeyExchangeException.class);
//    thrown.expectMslError(MslError.KEYX_RESPONSE_REQUEST_MISMATCH);

    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(KEYPAIR_ID + "A", AsymmetricWrappedExchange::RequestData::Mechanism::JWK_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
    shared_ptr<KeyExchangeData> keyxData = factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;
    shared_ptr<MasterToken>masterToken = keyResponseData->getMasterToken();

    shared_ptr<KeyResponseData> mismatchedKeyResponseData = make_shared<ResponseData>(masterToken, KEYPAIR_ID + "B", ENCRYPTION_KEY, HMAC_KEY);

    try {
        factory->getCryptoContext(ctx, keyRequestData, mismatchedKeyResponseData, shared_ptr<MasterToken>());
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslKeyExchangeException& e) {
        EXPECT_EQ(MslError::KEYX_RESPONSE_REQUEST_MISMATCH, e.getError());
    }
}

TEST_F(AsymmetricWrappedExchange_KeyExchangeFactoryTest, missingPrivateKeyCryptoContext)
{
//    thrown.expect(MslKeyExchangeException.class);
//    thrown.expectMslError(MslError.KEYX_PRIVATE_KEY_MISSING);

    shared_ptr<KeyRequestData> keyRequestData = make_shared<RequestData>(KEYPAIR_ID + "B", RequestData::Mechanism::JWK_RSA, RSA_PUBLIC_KEY, std::shared_ptr<crypto::PrivateKey>());
    shared_ptr<KeyExchangeData> keyxData = factory->generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
    shared_ptr<KeyResponseData> keyResponseData = keyxData->keyResponseData;

    try {
        factory->getCryptoContext(ctx, keyRequestData, keyResponseData, shared_ptr<tokens::MasterToken>());
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslKeyExchangeException& e) {
        EXPECT_EQ(MslError::KEYX_PRIVATE_KEY_MISSING, e.getError());
    }
}

}}} // namespace netflix::msl::keyx
