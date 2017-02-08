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
    static PublicKey getPublicKey() { return keyInstance().first; }
    static PrivateKey getPrivateKey() { return keyInstance().second; }
private:
    static pair<PublicKey,PrivateKey> keyInstance() {
        static pair<PublicKey,PrivateKey> theInstance;
        if (theInstance.first.isNull())
            theInstance = MslTestUtils::generateRsaKeys("RSA", 512);
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
    , RSA_PUBLIC_KEY(make_shared<PublicKey>(TestSingleton::getPublicKey()))
    , RSA_PRIVATE_KEY(make_shared<PrivateKey>(TestSingleton::getPrivateKey()))
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

//    /** Authentication utilities. */
//    private static MockAuthenticationUtils authutils;
//    /** Random. */
//    shared_ptr<IRandom> random;
//    /** Key exchange factory. */
//    private static KeyExchangeFactory factory;
//    /** Entity authentication data. */
//    private static EntityAuthenticationData entityAuthData;
};

struct TestParameters
{
    const RequestData::Mechanism mechanism;
    PublicKey publicKey;
    PrivateKey privateKey;
    TestParameters(const RequestData::Mechanism& m,
        PublicKey pubk, PrivateKey privk)
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
    EXPECT_EQ(*GetParam().privateKey.getEncoded(), *req.getPrivateKey().getEncoded());
    EXPECT_EQ(*GetParam().publicKey.getEncoded(), *req.getPublicKey().getEncoded());
    shared_ptr<MslObject> keydata = req.getKeydata(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(keydata);

    const RequestData moReq(keydata);
    EXPECT_EQ(req.getKeyExchangeScheme(), moReq.getKeyExchangeScheme());
    EXPECT_EQ(req.getKeyPairId(), moReq.getKeyPairId());
    EXPECT_EQ(req.getMechanism(), moReq.getMechanism());
    EXPECT_TRUE(moReq.getPrivateKey().isNull());
    EXPECT_EQ(*req.getPublicKey().getEncoded(), *moReq.getPublicKey().getEncoded());
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
    EXPECT_EQ(*GetParam().publicKey.getEncoded(), *keydata->getBytes(KEY_PUBLIC_KEY));
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
    EXPECT_TRUE(moData->getPrivateKey().isNull());
    EXPECT_EQ(*data->getPublicKey().getEncoded(), *moData->getPublicKey().getEncoded());
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

    shared_ptr<ByteArray> encodedKey = GetParam().publicKey.getEncoded();
    shared_ptr<ByteArray> shortKey = make_shared<ByteArray>();
    keydata->put(KEY_PUBLIC_KEY, shortKey);

    try {
        RequestData requestData(keydata);
        ADD_FAILURE() << "Should have thrown";
    } catch(const MslCryptoException& e) {
        EXPECT_EQ(MslError::INVALID_PUBLIC_KEY, e.getError());
    }
}

#if 0
        @Test
        public void equalsKeyPairId() throws MslEncodingException, MslCryptoException, MslKeyExchangeException, MslException {
            final RequestData dataA = new RequestData(KEYPAIR_ID + "A", Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final RequestData dataB = new RequestData(KEYPAIR_ID + "B", Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final RequestData dataA2 = new RequestData(dataA.getKeydata(encoder, ENCODER_FORMAT));

            assertTrue(dataA.equals(dataA));
            EXPECT_EQ(dataA.hashCode(), dataA.hashCode());

            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());

            // The private keys don't transfer via the parse constructor.
            assertFalse(dataA.equals(dataA2));
            assertFalse(dataA2.equals(dataA));
            assertTrue(dataA.hashCode() != dataA2.hashCode());
        }

        @Test
        public void equalsMechanism() throws MslEncodingException, MslCryptoException, MslKeyExchangeException, MslException {
            final RequestData dataA = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final RequestData dataB = new RequestData(KEYPAIR_ID, Mechanism.ECC, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final RequestData dataA2 = new RequestData(dataA.getKeydata(encoder, ENCODER_FORMAT));

            assertTrue(dataA.equals(dataA));
            EXPECT_EQ(dataA.hashCode(), dataA.hashCode());

            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());

            // The private keys don't transfer via the parse constructor.
            assertFalse(dataA.equals(dataA2));
            assertFalse(dataA2.equals(dataA));
            assertTrue(dataA.hashCode() != dataA2.hashCode());
        }

        @Test
        public void equalsPublicKey() throws MslEncodingException, MslCryptoException, MslKeyExchangeException, MslException {
            final RequestData dataA = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final RequestData dataB = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, ECC_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final RequestData dataA2 = new RequestData(dataA.getKeydata(encoder, ENCODER_FORMAT));

            assertTrue(dataA.equals(dataA));
            EXPECT_EQ(dataA.hashCode(), dataA.hashCode());

            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());

            // The private keys don't transfer via the parse constructor.
            assertFalse(dataA.equals(dataA2));
            assertFalse(dataA2.equals(dataA));
            assertTrue(dataA.hashCode() != dataA2.hashCode());
        }

        @Test
        public void equalsPrivateKey() throws MslEncodingException, MslCryptoException, MslKeyExchangeException, MslException {
            final RequestData dataA = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final RequestData dataB = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_PUBLIC_KEY, ECC_PRIVATE_KEY);
            final RequestData dataA2 = new RequestData(dataA.getKeydata(encoder, ENCODER_FORMAT));

            assertTrue(dataA.equals(dataA));
            EXPECT_EQ(dataA.hashCode(), dataA.hashCode());

            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());

            // The private keys don't transfer via the parse constructor.
            assertFalse(dataA.equals(dataA2));
            assertFalse(dataA2.equals(dataA));
            assertTrue(dataA.hashCode() != dataA2.hashCode());
        }

        @Test
        public void equalsObject() {
            final RequestData data = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            assertFalse(data.equals(null));
            assertFalse(data.equals(IDENTITY));
            assertTrue(data.hashCode() != IDENTITY.hashCode());
        }
    }

    /** Response data unit tests. */
    public static class ResponseDataTest {
        /** Key master token. */
        private static final String KEY_MASTER_TOKEN = "mastertoken";

        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();

        @Test
        public void ctors() throws MslEncodingException, MslException, MslKeyExchangeException, MslEncoderException {
            final ResponseData resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            EXPECT_EQ(ENCRYPTION_KEY, resp.getEncryptionKey());
            EXPECT_EQ(HMAC_KEY, resp.getHmacKey());
            EXPECT_EQ(KeyExchangeScheme::ASYMMETRIC_WRAPPED, resp.getKeyExchangeScheme());
            EXPECT_EQ(KEYPAIR_ID, resp.getKeyPairId());
            EXPECT_EQ(MASTER_TOKEN, resp.getMasterToken());
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);
            EXPECT_TRUE(keydata);

            final ResponseData moResp = new ResponseData(MASTER_TOKEN, keydata);
            EXPECT_EQ(resp.getEncryptionKey(), moResp.getEncryptionKey());
            EXPECT_EQ(resp.getHmacKey(), moResp.getHmacKey());
            EXPECT_EQ(resp.getKeyExchangeScheme(), moResp.getKeyExchangeScheme());
            EXPECT_EQ(resp.getKeyPairId(), moResp.getKeyPairId());
            EXPECT_EQ(resp.getMasterToken(), moResp.getMasterToken());
            final MslObject moKeydata = moResp.getKeydata(encoder, ENCODER_FORMAT);
            EXPECT_TRUE(moKeydata);
            assertTrue(MslEncoderUtils.equalObjects(keydata, moKeydata));
        }

        @Test
        public void mslObject() throws MslException, MslEncodingException, MslCryptoException, MslException, MslEncoderException {
            final ResponseData resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            final MslObject mo = MslTestUtils.toMslObject(encoder, resp);
            EXPECT_EQ(KeyExchangeScheme::ASYMMETRIC_WRAPPED.toString(), mo.getString(KEY_SCHEME));
            final MasterToken masterToken = new MasterToken(ctx, mo.getMslObject(KEY_MASTER_TOKEN, encoder));
            EXPECT_EQ(MASTER_TOKEN, masterToken);
            final MslObject keydata = mo.getMslObject(KEY_KEYDATA, encoder);
            EXPECT_EQ(KEYPAIR_ID, keydata.getString(KEY_KEY_PAIR_ID));
            EXPECT_EQ(ENCRYPTION_KEY, keydata.getBytes(KEY_ENCRYPTION_KEY));
            EXPECT_EQ(HMAC_KEY, keydata.getBytes(KEY_HMAC_KEY));
        }

        @Test
        public void create() throws MslException, MslException, MslEncoderException {
            final ResponseData data = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, data);
            final KeyResponseData keyResponseData = KeyResponseData.create(ctx, mo);
            EXPECT_TRUE(keyResponseData);
            assertTrue(keyResponseData instanceof ResponseData);

            final ResponseData moData = (ResponseData)keyResponseData;
            EXPECT_EQ(data.getEncryptionKey(), moData->getEncryptionKey());
            EXPECT_EQ(data.getHmacKey(), moData->getHmacKey());
            EXPECT_EQ(data.getKeyExchangeScheme(), moData->getKeyExchangeScheme());
            EXPECT_EQ(data.getKeyPairId(), moData->getKeyPairId());
            EXPECT_EQ(data.getMasterToken(), moData->getMasterToken());
        }

        @Test
        public void missingKeyPairId() throws MslEncodingException, MslException, MslKeyExchangeException, MslEncoderException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final ResponseData resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);

            EXPECT_TRUE(keydata.remove(KEY_KEY_PAIR_ID));

            new ResponseData(MASTER_TOKEN, keydata);
        }

        @Test
        public void missingEncryptionKey() throws MslException, MslEncodingException, MslKeyExchangeException, MslEncoderException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final ResponseData resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);

            EXPECT_TRUE(keydata.remove(KEY_ENCRYPTION_KEY));

            new ResponseData(MASTER_TOKEN, keydata);
        }

        @Test
        public void missingHmacKey() throws MslException, MslEncodingException, MslKeyExchangeException, MslEncoderException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final ResponseData resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);

            EXPECT_TRUE(keydata.remove(KEY_HMAC_KEY));

            new ResponseData(MASTER_TOKEN, keydata);
        }

        @Test
        public void equalsMasterToken() throws MslEncodingException, MslException, MslCryptoException, MslKeyExchangeException, MslEncoderException {
            final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
            final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 1, 2);
            final ResponseData dataA = new ResponseData(masterTokenA, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            final ResponseData dataB = new ResponseData(masterTokenB, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            final ResponseData dataA2 = new ResponseData(masterTokenA, dataA.getKeydata(encoder, ENCODER_FORMAT));

            assertTrue(dataA.equals(dataA));
            EXPECT_EQ(dataA.hashCode(), dataA.hashCode());

            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());

            assertTrue(dataA.equals(dataA2));
            assertTrue(dataA2.equals(dataA));
            EXPECT_EQ(dataA.hashCode(), dataA2.hashCode());
        }

        @Test
        public void equalsKeyPairId() throws MslEncodingException, MslException, MslKeyExchangeException, MslEncoderException {
            final ResponseData dataA = new ResponseData(MASTER_TOKEN, KEYPAIR_ID + "A", ENCRYPTION_KEY, HMAC_KEY);
            final ResponseData dataB = new ResponseData(MASTER_TOKEN, KEYPAIR_ID + "B", ENCRYPTION_KEY, HMAC_KEY);
            final ResponseData dataA2 = new ResponseData(MASTER_TOKEN, dataA.getKeydata(encoder, ENCODER_FORMAT));

            assertTrue(dataA.equals(dataA));
            EXPECT_EQ(dataA.hashCode(), dataA.hashCode());

            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());

            assertTrue(dataA.equals(dataA2));
            assertTrue(dataA2.equals(dataA));
            EXPECT_EQ(dataA.hashCode(), dataA2.hashCode());
        }

        @Test
        public void equalsEncryptionKey() throws MslEncodingException, MslException, MslKeyExchangeException, MslEncoderException {
            shared_ptr<ByteArray> encryptionKeyA = Arrays.copyOf(ENCRYPTION_KEY, ENCRYPTION_KEY.length);
            shared_ptr<ByteArray> encryptionKeyB = Arrays.copyOf(ENCRYPTION_KEY, ENCRYPTION_KEY.length);
            ++encryptionKeyB[0];
            final ResponseData dataA = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, encryptionKeyA, HMAC_KEY);
            final ResponseData dataB = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, encryptionKeyB, HMAC_KEY);
            final ResponseData dataA2 = new ResponseData(MASTER_TOKEN, dataA.getKeydata(encoder, ENCODER_FORMAT));

            assertTrue(dataA.equals(dataA));
            EXPECT_EQ(dataA.hashCode(), dataA.hashCode());

            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());

            assertTrue(dataA.equals(dataA2));
            assertTrue(dataA2.equals(dataA));
            EXPECT_EQ(dataA.hashCode(), dataA2.hashCode());
        }

        @Test
        public void equalsHmacKey() throws MslEncodingException, MslException, MslKeyExchangeException, MslEncoderException {
            shared_ptr<ByteArray> hmacKeyA = Arrays.copyOf(HMAC_KEY, HMAC_KEY.length);
            shared_ptr<ByteArray> hmacKeyB = Arrays.copyOf(HMAC_KEY, HMAC_KEY.length);
            ++hmacKeyB[0];
            final ResponseData dataA = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, hmacKeyA);
            final ResponseData dataB = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, hmacKeyB);
            final ResponseData dataA2 = new ResponseData(MASTER_TOKEN, dataA.getKeydata(encoder, ENCODER_FORMAT));

            assertTrue(dataA.equals(dataA));
            EXPECT_EQ(dataA.hashCode(), dataA.hashCode());

            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());

            assertTrue(dataA.equals(dataA2));
            assertTrue(dataA2.equals(dataA));
            EXPECT_EQ(dataA.hashCode(), dataA2.hashCode());
        }

        @Test
        public void equalsObject() {
            final ResponseData data = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            assertFalse(data.equals(null));
            assertFalse(data.equals(IDENTITY));
            assertTrue(data.hashCode() != IDENTITY.hashCode());
        }
    }

    /** Key exchange factory unit tests. */
    public static class KeyExchangeFactoryTest {
        /**
         * Fake key request data for the asymmetric wrapped key exchange
         * scheme.
         */
        private static class FakeKeyRequestData extends KeyRequestData {
            /** Create a new fake key request data. */
            protected FakeKeyRequestData() {
                super(KeyExchangeScheme::ASYMMETRIC_WRAPPED);
            }

            /* (non-Javadoc)
             * @see com.netflix.msl.keyx.KeyRequestData#getKeydata(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
             */
            @Override
            protected MslObject getKeydata(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
                return null;
            }
        }

        /**
         * Fake key response data for the asymmetric wrapped key exchange
         * scheme.
         */
        private static class FakeKeyResponseData extends KeyResponseData {
            /** Create a new fake key response data. */
            protected FakeKeyResponseData() {
                super(MASTER_TOKEN, KeyExchangeScheme::ASYMMETRIC_WRAPPED);
            }

            /* (non-Javadoc)
             * @see com.netflix.msl.keyx.KeyResponseData#getKeydata(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
             */
            @Override
            protected MslObject getKeydata(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
                return null;
            }
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
        private static MasterToken getUntrustedMasterToken(final MslContext ctx, final SecretKey encryptionKey, final SecretKey hmacKey) throws MslEncodingException, MslCryptoException, MslException, MslException, MslEncoderException {
            final Date renewalWindow = new Date(System.currentTimeMillis() + 1000);
            final Date expiration = new Date(System.currentTimeMillis() + 2000);
            final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
            final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, 1L, 1L, null, identity, encryptionKey, hmacKey);
            final MslObject mo = MslTestUtils.toMslObject(encoder, masterToken);
            shared_ptr<ByteArray> signature = mo.getBytes("signature");
            ++signature[1];
            mo.put("signature", signature);
            final MasterToken untrustedMasterToken = new MasterToken(ctx, mo);
            return untrustedMasterToken;
        }

        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();

        @BeforeClass
        public static synchronized void setup() {
            Security.addProvider(new BouncyCastleProvider());
            random = new Random();
            authutils = new MockAuthenticationUtils();
            factory = new AsymmetricWrappedExchange(authutils);
            entityAuthData = new PresharedAuthenticationData(IDENTITY);
        }

        @AfterClass
        public static void teardown() {
            // Do not cleanup so the static instances are available to
            // subclasses.
        }

        @Before
        public void reset() {
            authutils.reset();
            ctx.getMslStore().clearCryptoContexts();
            ctx.getMslStore().clearServiceTokens();
        }

        @RunWith(Parameterized.class)
        public static class Params {
            @Rule
            public ExpectedMslException thrown = ExpectedMslException.none();

            @Parameters
            public static Collection<Object[]> data() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MslEncodingException, MslCryptoException {
                AsymmetricWrappedExchangeSuite.setup();
                return Arrays.asList(new Object[][] {
                    { Mechanism.RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY },
                    { Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY },
                    { Mechanism.JWEJS_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY },
                    { Mechanism.JWK_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY },
                    { Mechanism.JWK_RSAES, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY },
                });
            }

            /** Key exchange mechanism. */
            private final Mechanism mechanism;
            /** Public key. */
            private final PublicKey publicKey;
            /** Private key. */
            private final PrivateKey privateKey;

            /**
             * Create a new request data test instance with the specified key
             * exchange parameters.
             *
             * @param mechanism key exchange mechanism.
             * @param publicKey public key.
             * @param privateKey private key.
             */
            public Params(final Mechanism mechanism, final PublicKey publicKey, final PrivateKey privateKey) {
                this.mechanism = mechanism;
                this.publicKey = publicKey;
                this.privateKey = privateKey;
            }

            @Test
            public void generateInitialResponse() throws MslException, MslException {
                final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
                EXPECT_TRUE(keyxData);
                EXPECT_TRUE(keyxData.cryptoContext);
                EXPECT_TRUE(keyxData.keyResponseData);

                final KeyResponseData keyResponseData = keyxData.keyResponseData;
                EXPECT_EQ(KeyExchangeScheme::ASYMMETRIC_WRAPPED, keyResponseData.getKeyExchangeScheme());
                final MasterToken masterToken = keyResponseData.getMasterToken();
                EXPECT_TRUE(masterToken);
                EXPECT_EQ(IDENTITY, masterToken.getIdentity());
            }

            @Test
            public void generateSubsequentResponse() throws MslException {
                final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN);
                EXPECT_TRUE(keyxData);
                EXPECT_TRUE(keyxData.cryptoContext);
                EXPECT_TRUE(keyxData.keyResponseData);

                final KeyResponseData keyResponseData = keyxData.keyResponseData;
                EXPECT_EQ(KeyExchangeScheme::ASYMMETRIC_WRAPPED, keyResponseData.getKeyExchangeScheme());
                final MasterToken masterToken = keyResponseData.getMasterToken();
                EXPECT_TRUE(masterToken);
                EXPECT_EQ(MASTER_TOKEN.getIdentity(), masterToken.getIdentity());
                EXPECT_EQ(MASTER_TOKEN.getSerialNumber(), masterToken.getSerialNumber());
                EXPECT_EQ(MASTER_TOKEN.getSequenceNumber() + 1, masterToken.getSequenceNumber());
            }

            @Test
            public void untrustedMasterTokenSubsequentResponse() throws MslEncodingException, MslCryptoException, MslException, MslException, MslEncoderException {
                thrown.expect(MslMasterTokenException.class);

                final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
                final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
                final MasterToken masterToken = getUntrustedMasterToken(ctx, encryptionKey, hmacKey);
                factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, masterToken);
            }

            @Test
            public void getCryptoContext() throws MslException {
                final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
                final ICryptoContext requestCryptoContext = keyxData.cryptoContext;
                final KeyResponseData keyResponseData = keyxData.keyResponseData;
                final ICryptoContext responseCryptoContext = factory.getCryptoContext(ctx, keyRequestData, keyResponseData, null);
                EXPECT_TRUE(responseCryptoContext);

                shared_ptr<ByteArray> data = new byte[32];
                random.nextBytes(data);

                // Ciphertext won't always be equal depending on how it was
                // enveloped. So we cannot check for equality or inequality.
                shared_ptr<ByteArray> requestCiphertext = requestCryptoContext.encrypt(data, encoder, ENCODER_FORMAT);
                shared_ptr<ByteArray> responseCiphertext = responseCryptoContext.encrypt(data, encoder, ENCODER_FORMAT);
                assertFalse(Arrays.equals(data, requestCiphertext));
                assertFalse(Arrays.equals(data, responseCiphertext));

                // Signatures should always be equal.
                shared_ptr<ByteArray> requestSignature = requestCryptoContext.sign(data, encoder, ENCODER_FORMAT);
                shared_ptr<ByteArray> responseSignature = responseCryptoContext.sign(data, encoder, ENCODER_FORMAT);
                assertFalse(Arrays.equals(data, requestSignature));
                assertFalse(Arrays.equals(data, responseSignature));
                EXPECT_EQ(requestSignature, responseSignature);

                // Plaintext should always be equal to the original message.
                shared_ptr<ByteArray> requestPlaintext = requestCryptoContext.decrypt(responseCiphertext, encoder);
                shared_ptr<ByteArray> responsePlaintext = responseCryptoContext.decrypt(requestCiphertext, encoder);
                EXPECT_TRUE(requestPlaintext);
                EXPECT_EQ(data, requestPlaintext);
                EXPECT_EQ(requestPlaintext, responsePlaintext);

                // Verification should always succeed.
                assertTrue(requestCryptoContext.verify(data, responseSignature, encoder));
                assertTrue(responseCryptoContext.verify(data, requestSignature, encoder));
            }

            @Test
            public void invalidWrappedEncryptionKeyCryptoContext() throws MslException, MslException, MslEncoderException {
                thrown.expect(MslCryptoException.class);

                final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
                final KeyResponseData keyResponseData = keyxData.keyResponseData;
                final MasterToken masterToken = keyResponseData.getMasterToken();

                final MslObject keydata = keyResponseData.getKeydata(encoder, ENCODER_FORMAT);
                shared_ptr<ByteArray> wrappedEncryptionKey = keydata.getBytes(KEY_ENCRYPTION_KEY);
                // I think I have to change length - 2 because of padding.
                ++wrappedEncryptionKey[wrappedEncryptionKey.length-2];
                keydata.put(KEY_ENCRYPTION_KEY, wrappedEncryptionKey);
                shared_ptr<ByteArray> wrappedHmacKey = keydata.getBytes(KEY_HMAC_KEY);

                final KeyResponseData invalidKeyResponseData = new ResponseData(masterToken, KEYPAIR_ID, wrappedEncryptionKey, wrappedHmacKey);
                factory.getCryptoContext(ctx, keyRequestData, invalidKeyResponseData, null);
            }

            @Test
            public void invalidWrappedHmacKeyCryptoContext() throws MslException, MslException, MslEncoderException {
                thrown.expect(MslCryptoException.class);

                final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
                final KeyResponseData keyResponseData = keyxData.keyResponseData;
                final MasterToken masterToken = keyResponseData.getMasterToken();

                final MslObject keydata = keyResponseData.getKeydata(encoder, ENCODER_FORMAT);
                shared_ptr<ByteArray> wrappedHmacKey = keydata.getBytes(KEY_HMAC_KEY);
                // I think I have to change length - 2 because of padding.
                ++wrappedHmacKey[wrappedHmacKey.length-2];
                keydata.put(KEY_HMAC_KEY, wrappedHmacKey);
                shared_ptr<ByteArray> wrappedEncryptionKey = keydata.getBytes(KEY_ENCRYPTION_KEY);

                final KeyResponseData invalidKeyResponseData = new ResponseData(masterToken, KEYPAIR_ID, wrappedEncryptionKey, wrappedHmacKey);
                factory.getCryptoContext(ctx, keyRequestData, invalidKeyResponseData, null);
            }
        }

        @Test
        public void factory() {
            EXPECT_EQ(KeyExchangeScheme::ASYMMETRIC_WRAPPED, factory.getScheme());
        }

        @Test(expected = MslInternalException.class)
        public void wrongRequestInitialResponse() throws MslInternalException, MslException {
            final KeyRequestData keyRequestData = new FakeKeyRequestData();
            factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
        }

        @Test(expected = MslInternalException.class)
        public void wrongRequestSubsequentResponse() throws MslInternalException, MslException {
            final KeyRequestData keyRequestData = new FakeKeyRequestData();
            factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN);
        }

        @Test(expected = MslInternalException.class)
        public void wrongRequestCryptoContext() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;

            final KeyRequestData fakeKeyRequestData = new FakeKeyRequestData();
            factory.getCryptoContext(ctx, fakeKeyRequestData, keyResponseData, null);
        }

        @Test(expected = MslInternalException.class)
        public void wrongResponseCryptoContext() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslMasterTokenException, MslEntityAuthException {
            final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final KeyResponseData fakeKeyResponseData = new FakeKeyResponseData();
            factory.getCryptoContext(ctx, keyRequestData, fakeKeyResponseData, null);
        }

        @Test
        public void keyIdMismatchCryptoContext() throws MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.KEYX_RESPONSE_REQUEST_MISMATCH);

            final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID + "A", Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            final MasterToken masterToken = keyResponseData.getMasterToken();

            final KeyResponseData mismatchedKeyResponseData = new ResponseData(masterToken, KEYPAIR_ID + "B", ENCRYPTION_KEY, HMAC_KEY);

            factory.getCryptoContext(ctx, keyRequestData, mismatchedKeyResponseData, null);
        }

        @Test
        public void missingPrivateKeyCryptoContext() throws MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.KEYX_PRIVATE_KEY_MISSING);

            final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID + "B", Mechanism.JWE_RSA, RSA_PUBLIC_KEY, null);
            final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;

            factory.getCryptoContext(ctx, keyRequestData, keyResponseData, null);
        }

    }
}
#endif

}}} // namespace netflix::msl::keyx
