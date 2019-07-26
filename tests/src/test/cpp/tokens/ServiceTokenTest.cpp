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

#include <gtest/gtest.h>
#include <tokens/ServiceToken.h>
#include <tokens/MasterToken.h>
#include <tokens/UserIdToken.h>
#include <crypto/IRandom.h>
#include <crypto/JcaAlgorithm.h>
#include <crypto/Key.h>
#include <crypto/SymmetricCryptoContext.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslException.h>
#include <MslInternalException.h>
#include <util/MslContext.h>
#include <memory>
#include <ostream>

#include <tokens/MockMslUser.h>
#include <util/MockMslContext.h>
#include <util/MslTestUtils.h>

using namespace std;
using namespace testing;
using namespace netflix::msl;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace tokens {

namespace {

/** Key token data. */
const string KEY_TOKENDATA = "tokendata";
/** Key signature. */
const string KEY_SIGNATURE = "signature";

// tokendata
/** Key token name. */
const string KEY_NAME = "name";
/** Key master token serial number. */
const string KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
/** Key user ID token serial number. */
const string KEY_USER_ID_TOKEN_SERIAL_NUMBER = "uitserialnumber";
/** Key encrypted. */
const string KEY_ENCRYPTED = "encrypted";
/** Key compression algorithm. */
const string KEY_COMPRESSION_ALGORITHM = "compressionalgo";
/** Key service data. */
const string KEY_SERVICEDATA = "servicedata";

const string NAME = "tokenName";

const string DATASTR =
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ";

/**
 * @param ctx MSL context.
 * @return a new crypto context.
 * @throws CryptoException if there is an error creating the crypto
 *         context.
 */
shared_ptr<ICryptoContext> getCryptoContext(shared_ptr<MslContext> ctx)
{
    const string keysetId = "keysetId";
    shared_ptr<ByteArray> encryptionBytes = make_shared<ByteArray>(16);
    ctx->getRandom()->nextBytes(*encryptionBytes);
    const SecretKey encryptionKey(encryptionBytes, JcaAlgorithm::AES);
    shared_ptr<ByteArray> hmacBytes = make_shared<ByteArray>(32);
    ctx->getRandom()->nextBytes(*hmacBytes);
    const SecretKey hmacKey(hmacBytes, JcaAlgorithm::HMAC_SHA256);
    const SecretKey nullKey;
    return make_shared<SymmetricCryptoContext>(ctx, keysetId, encryptionKey, hmacKey, nullKey);
}

struct TestParameters
{
    const MslConstants::CompressionAlgorithm compAlg;
    TestParameters(const MslConstants::CompressionAlgorithm& compAlg) : compAlg(compAlg) {}
    friend ostream & operator<<(ostream &os, const TestParameters& tp);
};
ostream & operator<<(ostream& os, const TestParameters& tp) {
    return os << "compression algorithm: " << tp.compAlg.toString();
}

string sufx(testing::TestParamInfo<struct TestParameters> tpi) {
    return tpi.param.compAlg.toString();
}

} // namespace anonymous

class ServiceTokenTest : public ::testing::TestWithParam<TestParameters>
{
public:
    ServiceTokenTest()
    : ctx(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false))
    , encoder(ctx->getMslEncoderFactory())
    , ENCODER_FORMAT(MslEncoderFormat::JSON)
    , DATA(make_shared<ByteArray>(DATASTR.begin(), DATASTR.end()))
    , MASTER_TOKEN(MslTestUtils::getMasterToken(ctx, 1, 1))
    , USER(make_shared<MockMslUser>(312204600))
    , USER_ID_TOKEN(MslTestUtils::getUserIdToken(ctx, MASTER_TOKEN, 1, USER))
    , ENCRYPTED(true)
    , CRYPTO_CONTEXT(getCryptoContext(ctx))
    {

    }
protected:
    /** MSL context. */
    shared_ptr <MslContext> ctx;
    /** MSL encoder factory. */
    shared_ptr<MslEncoderFactory> encoder;
    /** MSL encoder format. */
    const MslEncoderFormat ENCODER_FORMAT;
    shared_ptr<ByteArray> DATA;
    shared_ptr<MasterToken> MASTER_TOKEN;
    shared_ptr<MslUser> USER;
    shared_ptr<UserIdToken> USER_ID_TOKEN;
    const bool ENCRYPTED;
    shared_ptr<ICryptoContext> CRYPTO_CONTEXT;
};

// Run each test with all types of CompressionAlgorithm
INSTANTIATE_TEST_CASE_P(ServiceToken, ServiceTokenTest,
    ::testing::Values(
            TestParameters(MslConstants::CompressionAlgorithm::NOCOMPRESSION),
//            TestParameters(MslConstants::CompressionAlgorithm::LZW),  // LZW has been removed
            TestParameters(MslConstants::CompressionAlgorithm::GZIP)
    ), &sufx);

TEST_P(ServiceTokenTest, ctors)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    EXPECT_TRUE(serviceToken->isDecrypted());
    EXPECT_FALSE(serviceToken->isDeleted());
    EXPECT_TRUE(serviceToken->isVerified());
    EXPECT_TRUE(serviceToken->isBoundTo(MASTER_TOKEN));
    EXPECT_TRUE(serviceToken->isBoundTo(USER_ID_TOKEN));
    EXPECT_TRUE(serviceToken->isMasterTokenBound());
    EXPECT_TRUE(serviceToken->isUserIdTokenBound());
    EXPECT_FALSE(serviceToken->isUnbound());
    EXPECT_EQ(MASTER_TOKEN->getSerialNumber(), serviceToken->getMasterTokenSerialNumber());
    EXPECT_EQ(USER_ID_TOKEN->getSerialNumber(), serviceToken->getUserIdTokenSerialNumber());
    EXPECT_EQ(NAME, serviceToken->getName());
    EXPECT_EQ(GetParam().compAlg, serviceToken->getCompressionAlgo());
    EXPECT_EQ(DATA, serviceToken->getData());
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(encode);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ServiceToken> moServiceToken = make_shared<ServiceToken>(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    EXPECT_EQ(serviceToken->isDecrypted(), moServiceToken->isDecrypted());
    EXPECT_EQ(serviceToken->isDeleted(), moServiceToken->isDeleted());
    EXPECT_EQ(serviceToken->isVerified(), moServiceToken->isVerified());
    EXPECT_EQ(serviceToken->isBoundTo(MASTER_TOKEN), moServiceToken->isBoundTo(MASTER_TOKEN));
    EXPECT_EQ(serviceToken->isBoundTo(USER_ID_TOKEN), moServiceToken->isBoundTo(USER_ID_TOKEN));
    EXPECT_EQ(serviceToken->isMasterTokenBound(), moServiceToken->isMasterTokenBound());
    EXPECT_EQ(serviceToken->isUserIdTokenBound(), moServiceToken->isUserIdTokenBound());
    EXPECT_EQ(serviceToken->isUnbound(), moServiceToken->isUnbound());
    EXPECT_EQ(serviceToken->getMasterTokenSerialNumber(), moServiceToken->getMasterTokenSerialNumber());
    EXPECT_EQ(serviceToken->getUserIdTokenSerialNumber(), moServiceToken->getUserIdTokenSerialNumber());
    EXPECT_EQ(serviceToken->getName(), moServiceToken->getName());
    EXPECT_EQ(serviceToken->getCompressionAlgo(), moServiceToken->getCompressionAlgo());
    EXPECT_EQ(*serviceToken->getData(), *moServiceToken->getData());
    shared_ptr<ByteArray> moEncode = moServiceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(encode);
    EXPECT_EQ(*encode, *moEncode);
}

TEST_P(ServiceTokenTest, cryptoContextMismatch)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ICryptoContext> moCryptoContext = getCryptoContext(ctx);
    shared_ptr<ServiceToken> moServiceToken = make_shared<ServiceToken>(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, moCryptoContext);
    EXPECT_FALSE(moServiceToken->isDecrypted());
    EXPECT_FALSE(serviceToken->isDeleted());
    EXPECT_FALSE(moServiceToken->isVerified());
    EXPECT_FALSE(moServiceToken->getData());
    EXPECT_EQ(serviceToken->isBoundTo(MASTER_TOKEN), moServiceToken->isBoundTo(MASTER_TOKEN));
    EXPECT_EQ(serviceToken->isBoundTo(USER_ID_TOKEN), moServiceToken->isBoundTo(USER_ID_TOKEN));
    EXPECT_EQ(serviceToken->isMasterTokenBound(), moServiceToken->isMasterTokenBound());
    EXPECT_EQ(serviceToken->isUserIdTokenBound(), moServiceToken->isUserIdTokenBound());
    EXPECT_EQ(serviceToken->isUnbound(), moServiceToken->isUnbound());
    EXPECT_EQ(serviceToken->getMasterTokenSerialNumber(), moServiceToken->getMasterTokenSerialNumber());
    EXPECT_EQ(serviceToken->getUserIdTokenSerialNumber(), moServiceToken->getUserIdTokenSerialNumber());
    EXPECT_EQ(serviceToken->getName(), moServiceToken->getName());
    EXPECT_EQ(serviceToken->getCompressionAlgo(), moServiceToken->getCompressionAlgo());
    shared_ptr<ByteArray> moEncode = moServiceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_EQ(*encode, *moEncode);
}

TEST_P(ServiceTokenTest, mappedCryptoContext)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    map<string, shared_ptr<ICryptoContext>> cryptoContexts;
    cryptoContexts.insert(make_pair(NAME, CRYPTO_CONTEXT));
    cryptoContexts.insert(make_pair(NAME + "1", getCryptoContext(ctx)));
    cryptoContexts.insert(make_pair(NAME + "2", getCryptoContext(ctx)));

    shared_ptr<ServiceToken> moServiceToken = make_shared<ServiceToken>(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, cryptoContexts);
    EXPECT_EQ(serviceToken->isDecrypted(), moServiceToken->isDecrypted());
    EXPECT_EQ(serviceToken->isDeleted(), moServiceToken->isDeleted());
    EXPECT_EQ(serviceToken->isVerified(), moServiceToken->isVerified());
    EXPECT_EQ(serviceToken->isBoundTo(MASTER_TOKEN), moServiceToken->isBoundTo(MASTER_TOKEN));
    EXPECT_EQ(serviceToken->isBoundTo(USER_ID_TOKEN), moServiceToken->isBoundTo(USER_ID_TOKEN));
    EXPECT_EQ(serviceToken->isMasterTokenBound(), moServiceToken->isMasterTokenBound());
    EXPECT_EQ(serviceToken->isUserIdTokenBound(), moServiceToken->isUserIdTokenBound());
    EXPECT_EQ(serviceToken->isUnbound(), moServiceToken->isUnbound());
    EXPECT_EQ(serviceToken->getMasterTokenSerialNumber(), moServiceToken->getMasterTokenSerialNumber());
    EXPECT_EQ(serviceToken->getUserIdTokenSerialNumber(), moServiceToken->getUserIdTokenSerialNumber());
    EXPECT_EQ(serviceToken->getName(), moServiceToken->getName());
    EXPECT_EQ(serviceToken->getCompressionAlgo(), moServiceToken->getCompressionAlgo());
    EXPECT_EQ(*serviceToken->getData(), *moServiceToken->getData());
    shared_ptr<ByteArray> moEncode = moServiceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_EQ(*encode, *moEncode);
}

TEST_P(ServiceTokenTest, unmappedCryptoContext)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    map<string, shared_ptr<ICryptoContext>> cryptoContexts;
    cryptoContexts.insert(make_pair(NAME + "0", CRYPTO_CONTEXT));
    cryptoContexts.insert(make_pair(NAME + "1", getCryptoContext(ctx)));
    cryptoContexts.insert(make_pair(NAME + "2", getCryptoContext(ctx)));

    shared_ptr<ServiceToken> moServiceToken = make_shared<ServiceToken>(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, cryptoContexts);
    EXPECT_FALSE(moServiceToken->isDecrypted());
    EXPECT_FALSE(moServiceToken->isDeleted());
    EXPECT_FALSE(moServiceToken->isVerified());
    EXPECT_FALSE(moServiceToken->getData());
    EXPECT_EQ(serviceToken->isBoundTo(MASTER_TOKEN), moServiceToken->isBoundTo(MASTER_TOKEN));
    EXPECT_EQ(serviceToken->isBoundTo(USER_ID_TOKEN), moServiceToken->isBoundTo(USER_ID_TOKEN));
    EXPECT_EQ(serviceToken->isMasterTokenBound(), moServiceToken->isMasterTokenBound());
    EXPECT_EQ(serviceToken->isUserIdTokenBound(), moServiceToken->isUserIdTokenBound());
    EXPECT_EQ(serviceToken->isUnbound(), moServiceToken->isUnbound());
    EXPECT_EQ(serviceToken->getMasterTokenSerialNumber(), moServiceToken->getMasterTokenSerialNumber());
    EXPECT_EQ(serviceToken->getUserIdTokenSerialNumber(), moServiceToken->getUserIdTokenSerialNumber());
    EXPECT_EQ(serviceToken->getName(), moServiceToken->getName());
    EXPECT_EQ(serviceToken->getCompressionAlgo(), moServiceToken->getCompressionAlgo());
    shared_ptr<ByteArray> moEncode = moServiceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_EQ(*encode, *moEncode);
}

TEST_P(ServiceTokenTest, masterTokenMismatch)
{
    shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, masterToken, shared_ptr<UserIdToken>(), ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<MasterToken> moMasterToken = MslTestUtils::getMasterToken(ctx, 1, 2);

    try {
        ServiceToken(ctx, mo, moMasterToken, shared_ptr<UserIdToken>(), CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::SERVICETOKEN_MASTERTOKEN_MISMATCH, e.getError());
    }
}

TEST_P(ServiceTokenTest, masterTokenMissing)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    try {
        ServiceToken(ctx, mo, shared_ptr<MasterToken>(), USER_ID_TOKEN, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::SERVICETOKEN_MASTERTOKEN_MISMATCH, e.getError());
    }
}

TEST_P(ServiceTokenTest, userIdTokenMismatch)
{
    shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, MASTER_TOKEN, 1, USER);
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, userIdToken, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<UserIdToken> moUserIdToken = MslTestUtils::getUserIdToken(ctx, MASTER_TOKEN, 2, USER);

    try {
        ServiceToken(ctx, mo, MASTER_TOKEN, moUserIdToken, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::SERVICETOKEN_USERIDTOKEN_MISMATCH, e.getError());
    }
}

TEST_P(ServiceTokenTest, userIdTokenMissing)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    try {
        ServiceToken(ctx, mo, MASTER_TOKEN, shared_ptr<UserIdToken>(), CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::SERVICETOKEN_USERIDTOKEN_MISMATCH, e.getError());
    }
}

TEST_P(ServiceTokenTest, tokenMismatch)
{
    shared_ptr<MasterToken> masterTokenA = MslTestUtils::getMasterToken(ctx, 1, 1);
    shared_ptr<MasterToken> masterTokenB = MslTestUtils::getMasterToken(ctx, 1, 2);
    shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterTokenB, 1, USER);
    EXPECT_THROW(ServiceToken(ctx, NAME, DATA, masterTokenA, userIdToken, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT), MslInternalException);
}

TEST_P(ServiceTokenTest, missingTokendata)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    EXPECT_FALSE(mo->remove(KEY_TOKENDATA).isNull());

    try {
        ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_P(ServiceTokenTest, invalidTokendata)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    ++(*tokendata)[0];
    mo->put(KEY_TOKENDATA, tokendata);

    try {
        ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_P(ServiceTokenTest, missingSignature)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    EXPECT_FALSE(mo->remove(KEY_SIGNATURE).isNull());

    try {
        ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_P(ServiceTokenTest, missingName)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);;
    EXPECT_FALSE(tokendataMo->remove(KEY_NAME).isNull());
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_P(ServiceTokenTest, missingMasterTokenSerialNumber)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);;
    EXPECT_FALSE(tokendataMo->remove(KEY_MASTER_TOKEN_SERIAL_NUMBER).isNull());
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    shared_ptr<ServiceToken> moServiceToken = make_shared<ServiceToken>(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    EXPECT_EQ(-1, moServiceToken->getMasterTokenSerialNumber());
    EXPECT_FALSE(moServiceToken->isBoundTo(MASTER_TOKEN));
}

TEST_P(ServiceTokenTest, invalidMasterTokenSerialNumber)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);;
    tokendataMo->put<string>(KEY_MASTER_TOKEN_SERIAL_NUMBER, "x");
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_P(ServiceTokenTest, negativeMasterTokenSerialNumber)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);;
    tokendataMo->put(KEY_MASTER_TOKEN_SERIAL_NUMBER, -1);
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::SERVICETOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, e.getError());
    }
}

TEST_P(ServiceTokenTest, tooLargeMasterTokenSerialNumber)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);;
    tokendataMo->put<int64_t>(KEY_MASTER_TOKEN_SERIAL_NUMBER, MslConstants::MAX_LONG_VALUE + 1);
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::SERVICETOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, e.getError());
    }
}

TEST_P(ServiceTokenTest, missingUserIdTokenSerialNumber)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);;
    EXPECT_FALSE(tokendataMo->remove(KEY_USER_ID_TOKEN_SERIAL_NUMBER).isNull());
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    shared_ptr<ServiceToken> moServiceToken = make_shared<ServiceToken>(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    EXPECT_EQ(-1, moServiceToken->getUserIdTokenSerialNumber());
    EXPECT_FALSE(moServiceToken->isBoundTo(USER_ID_TOKEN));
}

TEST_P(ServiceTokenTest, invalidUserIdTokenSerialNumber)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);;
    tokendataMo->put<string>(KEY_USER_ID_TOKEN_SERIAL_NUMBER, "x");
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_P(ServiceTokenTest, negativeUserIdTokenSerialNumber)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);;
    tokendataMo->put(KEY_USER_ID_TOKEN_SERIAL_NUMBER, -1);
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::SERVICETOKEN_USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, e.getError());
    }
}

TEST_P(ServiceTokenTest, tooLargeUserIdTokenSerialNumber)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);;
    tokendataMo->put<int64_t>(KEY_USER_ID_TOKEN_SERIAL_NUMBER, MslConstants::MAX_LONG_VALUE + 1);
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::SERVICETOKEN_USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, e.getError());
    }
}

TEST_P(ServiceTokenTest, missingEncrypted)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);;
    EXPECT_FALSE(tokendataMo->remove(KEY_ENCRYPTED).isNull());
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_P(ServiceTokenTest, invalidEncrypted)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);;
    tokendataMo->put<string>(KEY_ENCRYPTED, "x");
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_P(ServiceTokenTest, invalidCompressionAlgorithm)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);;
    tokendataMo->put<string>(KEY_COMPRESSION_ALGORITHM, "x");
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::UNIDENTIFIED_COMPRESSION, e.getError());
    }
}

TEST_P(ServiceTokenTest, missingServicedata)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);;
    EXPECT_FALSE(tokendataMo->remove(KEY_SERVICEDATA).isNull());
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_P(ServiceTokenTest, invalidServicedata)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);;
    tokendataMo->put(KEY_SERVICEDATA, false);

    shared_ptr<ByteArray> modifiedTokendata = encoder->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = CRYPTO_CONTEXT->sign(modifiedTokendata, encoder, ENCODER_FORMAT);
    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    try {
        ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_P(ServiceTokenTest, emptyServicedata)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, make_shared<ByteArray>(), MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    EXPECT_TRUE(serviceToken->isDeleted());
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ServiceToken> moServiceToken = make_shared<ServiceToken>(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    EXPECT_TRUE(moServiceToken->isDeleted());
    EXPECT_TRUE(moServiceToken->getData()->empty());
}

TEST_P(ServiceTokenTest, emptyServicedataNotVerified)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, make_shared<ByteArray>(), MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> signature = mo->getBytes(KEY_SIGNATURE);
    ++(*signature)[0];
    mo->put(KEY_SIGNATURE, signature);

    shared_ptr<ServiceToken> moServiceToken = make_shared<ServiceToken>(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    EXPECT_TRUE(moServiceToken->isDeleted());
    EXPECT_TRUE(moServiceToken->getData()->empty());
}

TEST_P(ServiceTokenTest, corruptServicedata)
{
//@Test(expected = MslCryptoException.class)
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    // This is testing service data that is verified but corrupt.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);;
    shared_ptr<ByteArray> servicedata = tokendataMo->getBytes(KEY_SERVICEDATA);
    ++(*servicedata)[servicedata->size()-1];
    tokendataMo->put(KEY_SERVICEDATA, servicedata);

    shared_ptr<ByteArray> modifiedTokendata = encoder->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = CRYPTO_CONTEXT->sign(modifiedTokendata, encoder, ENCODER_FORMAT);
    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    EXPECT_THROW(ServiceToken(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT), MslCryptoException);
}

TEST_P(ServiceTokenTest, notVerified)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> signature = mo->getBytes(KEY_SIGNATURE);
    ++(*signature)[0];
    mo->put(KEY_SIGNATURE, signature);

    shared_ptr<ServiceToken> moServiceToken = make_shared<ServiceToken>(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    EXPECT_FALSE(moServiceToken->isDecrypted());
    EXPECT_FALSE(moServiceToken->isDeleted());
    EXPECT_FALSE(moServiceToken->isVerified());
    EXPECT_FALSE(moServiceToken->getData());
    EXPECT_EQ(serviceToken->isBoundTo(MASTER_TOKEN), moServiceToken->isBoundTo(MASTER_TOKEN));
    EXPECT_EQ(serviceToken->isBoundTo(USER_ID_TOKEN), moServiceToken->isBoundTo(USER_ID_TOKEN));
    EXPECT_EQ(serviceToken->isMasterTokenBound(), moServiceToken->isMasterTokenBound());
    EXPECT_EQ(serviceToken->isUserIdTokenBound(), moServiceToken->isUserIdTokenBound());
    EXPECT_EQ(serviceToken->isUnbound(), moServiceToken->isUnbound());
    EXPECT_EQ(serviceToken->getMasterTokenSerialNumber(), moServiceToken->getMasterTokenSerialNumber());
    EXPECT_EQ(serviceToken->getUserIdTokenSerialNumber(), moServiceToken->getUserIdTokenSerialNumber());
    EXPECT_EQ(serviceToken->getName(), moServiceToken->getName());
    shared_ptr<ByteArray> moEncode = moServiceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_NE(encode, moEncode);
}

TEST_P(ServiceTokenTest, notEncrypted)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, !ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    EXPECT_EQ(DATA, serviceToken->getData());
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ServiceToken> moServiceToken = make_shared<ServiceToken>(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);
    EXPECT_TRUE(moServiceToken->isVerified());
    EXPECT_FALSE(moServiceToken->isDeleted());
    EXPECT_TRUE(moServiceToken->isDecrypted());
    EXPECT_EQ(*serviceToken->getData(), *moServiceToken->getData());
    EXPECT_EQ(serviceToken->isBoundTo(MASTER_TOKEN), moServiceToken->isBoundTo(MASTER_TOKEN));
    EXPECT_EQ(serviceToken->isBoundTo(USER_ID_TOKEN), moServiceToken->isBoundTo(USER_ID_TOKEN));
    EXPECT_EQ(serviceToken->isMasterTokenBound(), moServiceToken->isMasterTokenBound());
    EXPECT_EQ(serviceToken->isUserIdTokenBound(), moServiceToken->isUserIdTokenBound());
    EXPECT_EQ(serviceToken->isUnbound(), moServiceToken->isUnbound());
    EXPECT_EQ(serviceToken->getMasterTokenSerialNumber(), moServiceToken->getMasterTokenSerialNumber());
    EXPECT_EQ(serviceToken->getUserIdTokenSerialNumber(), moServiceToken->getUserIdTokenSerialNumber());
    EXPECT_EQ(serviceToken->getName(), moServiceToken->getName());
    shared_ptr<ByteArray> moEncode = moServiceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_EQ(*encode, *moEncode);
}

TEST_P(ServiceTokenTest, cryptoContextNull)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ServiceToken> moServiceToken = make_shared<ServiceToken>(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, shared_ptr<ICryptoContext>());
    EXPECT_FALSE(moServiceToken->isDecrypted());
    EXPECT_FALSE(moServiceToken->isDeleted());
    EXPECT_FALSE(moServiceToken->isVerified());
    EXPECT_FALSE(moServiceToken->getData());
    EXPECT_EQ(serviceToken->isBoundTo(MASTER_TOKEN), moServiceToken->isBoundTo(MASTER_TOKEN));
    EXPECT_EQ(serviceToken->isBoundTo(USER_ID_TOKEN), moServiceToken->isBoundTo(USER_ID_TOKEN));
    EXPECT_EQ(serviceToken->isMasterTokenBound(), moServiceToken->isMasterTokenBound());
    EXPECT_EQ(serviceToken->isUserIdTokenBound(), moServiceToken->isUserIdTokenBound());
    EXPECT_EQ(serviceToken->isUnbound(), moServiceToken->isUnbound());
    EXPECT_EQ(serviceToken->getMasterTokenSerialNumber(), moServiceToken->getMasterTokenSerialNumber());
    EXPECT_EQ(serviceToken->getUserIdTokenSerialNumber(), moServiceToken->getUserIdTokenSerialNumber());
    EXPECT_EQ(serviceToken->getName(), moServiceToken->getName());
    shared_ptr<ByteArray> moEncode = moServiceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_EQ(*encode, *moEncode);
}

TEST_P(ServiceTokenTest, notEncryptedCryptoContextNull)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, !ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ByteArray> encode = serviceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ServiceToken> moServiceToken = make_shared<ServiceToken>(ctx, mo, MASTER_TOKEN, USER_ID_TOKEN, shared_ptr<ICryptoContext>());
    EXPECT_FALSE(moServiceToken->isDecrypted());
    EXPECT_FALSE(moServiceToken->isDeleted());
    EXPECT_FALSE(moServiceToken->isVerified());
    EXPECT_FALSE(moServiceToken->getData());
    EXPECT_EQ(serviceToken->isBoundTo(MASTER_TOKEN), moServiceToken->isBoundTo(MASTER_TOKEN));
    EXPECT_EQ(serviceToken->isBoundTo(USER_ID_TOKEN), moServiceToken->isBoundTo(USER_ID_TOKEN));
    EXPECT_EQ(serviceToken->isMasterTokenBound(), moServiceToken->isMasterTokenBound());
    EXPECT_EQ(serviceToken->isUserIdTokenBound(), moServiceToken->isUserIdTokenBound());
    EXPECT_EQ(serviceToken->isUnbound(), moServiceToken->isUnbound());
    EXPECT_EQ(serviceToken->getMasterTokenSerialNumber(), moServiceToken->getMasterTokenSerialNumber());
    EXPECT_EQ(serviceToken->getUserIdTokenSerialNumber(), moServiceToken->getUserIdTokenSerialNumber());
    EXPECT_EQ(serviceToken->getName(), moServiceToken->getName());
    shared_ptr<ByteArray> moEncode = moServiceToken->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_EQ(*encode, *moEncode);
}

TEST_P(ServiceTokenTest, isBoundToMasterToken)
{
    shared_ptr<MasterToken> nullMasterToken;
    shared_ptr<MasterToken> masterTokenA = MslTestUtils::getMasterToken(ctx, 1, 1);
    shared_ptr<MasterToken> masterTokenB = MslTestUtils::getMasterToken(ctx, 1, 2);
    shared_ptr<UserIdToken> emptyUserIdToken;
    shared_ptr<ServiceToken> serviceTokenA = make_shared<ServiceToken>(ctx, NAME, DATA, masterTokenA, emptyUserIdToken, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ServiceToken> serviceTokenB = make_shared<ServiceToken>(ctx, NAME, DATA, masterTokenB, emptyUserIdToken, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);

    EXPECT_TRUE(serviceTokenA->isBoundTo(masterTokenA));
    EXPECT_FALSE(serviceTokenA->isBoundTo(masterTokenB));
    EXPECT_FALSE(serviceTokenA->isBoundTo(nullMasterToken));
    EXPECT_TRUE(serviceTokenB->isBoundTo(masterTokenB));
    EXPECT_FALSE(serviceTokenB->isBoundTo(masterTokenA));
    EXPECT_FALSE(serviceTokenA->isBoundTo(nullMasterToken));
}

TEST_P(ServiceTokenTest, isBoundToUserIdToken)
{
    shared_ptr<UserIdToken> nullUserIdToken;
    shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(ctx, MASTER_TOKEN, 1, USER);
    shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(ctx, MASTER_TOKEN, 2, USER);
    shared_ptr<ServiceToken> serviceTokenA = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, userIdTokenA, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ServiceToken> serviceTokenB = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, userIdTokenB, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);

    EXPECT_TRUE(serviceTokenA->isBoundTo(userIdTokenA));
    EXPECT_FALSE(serviceTokenA->isBoundTo(userIdTokenB));
    EXPECT_FALSE(serviceTokenA->isBoundTo(nullUserIdToken));
    EXPECT_TRUE(serviceTokenB->isBoundTo(userIdTokenB));
    EXPECT_FALSE(serviceTokenB->isBoundTo(userIdTokenA));
    EXPECT_FALSE(serviceTokenA->isBoundTo(nullUserIdToken));
}

TEST_P(ServiceTokenTest, isUnbound)
{
    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, NAME, DATA, shared_ptr<MasterToken>(), shared_ptr<UserIdToken>(), ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    EXPECT_TRUE(serviceToken->isUnbound());
    EXPECT_FALSE(serviceToken->isBoundTo(MASTER_TOKEN));
    EXPECT_FALSE(serviceToken->isBoundTo(USER_ID_TOKEN));
    shared_ptr<MasterToken> nullMasterToken;
    shared_ptr<UserIdToken> nullUserIdToken;
    EXPECT_FALSE(serviceToken->isBoundTo(nullMasterToken));
    EXPECT_FALSE(serviceToken->isBoundTo(nullUserIdToken));
}

TEST_P(ServiceTokenTest, equalsName)
{
    const string nameA = NAME + "A";
    const string nameB = NAME + "B";
    shared_ptr<ServiceToken> serviceTokenA = make_shared<ServiceToken>(ctx, nameA, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ServiceToken> serviceTokenB = make_shared<ServiceToken>(ctx, nameB, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ServiceToken> serviceTokenA2 = make_shared<ServiceToken>(ctx, MslTestUtils::toMslObject(encoder, serviceTokenA), MASTER_TOKEN, USER_ID_TOKEN, CRYPTO_CONTEXT);

    EXPECT_EQ(*serviceTokenA, *serviceTokenA);
    EXPECT_EQ(serviceTokenA->uniqueKey(), serviceTokenA->uniqueKey());

    EXPECT_NE(*serviceTokenA, *serviceTokenB);
    EXPECT_NE(*serviceTokenB, *serviceTokenA);
    EXPECT_NE(serviceTokenA->uniqueKey(), serviceTokenB->uniqueKey());

    EXPECT_EQ(*serviceTokenA, *serviceTokenA2);
    EXPECT_EQ(*serviceTokenA2, *serviceTokenA);
    EXPECT_EQ(serviceTokenA->uniqueKey(), serviceTokenA2->uniqueKey());
}

TEST_P(ServiceTokenTest, equalsMasterTokenSerialNumber)
{
    shared_ptr<MasterToken> masterTokenA = MslTestUtils::getMasterToken(ctx, 1, 1);
    shared_ptr<MasterToken> masterTokenB = MslTestUtils::getMasterToken(ctx, 1, 2);
    shared_ptr<UserIdToken> nullUserIdToken;
    shared_ptr<ServiceToken> serviceTokenA = make_shared<ServiceToken>(ctx, NAME, DATA, masterTokenA, nullUserIdToken, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ServiceToken> serviceTokenB = make_shared<ServiceToken>(ctx, NAME, DATA, masterTokenB, nullUserIdToken, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ServiceToken> serviceTokenA2 = make_shared<ServiceToken>(ctx, MslTestUtils::toMslObject(encoder, serviceTokenA), masterTokenA, nullUserIdToken, CRYPTO_CONTEXT);

    EXPECT_EQ(*serviceTokenA, *serviceTokenA);
    EXPECT_EQ(serviceTokenA->uniqueKey(), serviceTokenA->uniqueKey());

    EXPECT_NE(*serviceTokenA, *serviceTokenB);
    EXPECT_NE(*serviceTokenB, *serviceTokenA);
    EXPECT_NE(serviceTokenA->uniqueKey(), serviceTokenB->uniqueKey());

    EXPECT_EQ(*serviceTokenA, *serviceTokenA2);
    EXPECT_EQ(*serviceTokenA2, *serviceTokenA);
    EXPECT_EQ(serviceTokenA->uniqueKey(), serviceTokenA2->uniqueKey());
}

TEST_P(ServiceTokenTest, equalsUserIdTokenSerialNumber)
{
    shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(ctx, MASTER_TOKEN, 1, USER);
    shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(ctx, MASTER_TOKEN, 2, USER);
    shared_ptr<ServiceToken> serviceTokenA = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, userIdTokenA, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ServiceToken> serviceTokenB = make_shared<ServiceToken>(ctx, NAME, DATA, MASTER_TOKEN, userIdTokenB, ENCRYPTED, GetParam().compAlg, CRYPTO_CONTEXT);
    shared_ptr<ServiceToken> serviceTokenA2 = make_shared<ServiceToken>(ctx, MslTestUtils::toMslObject(encoder, serviceTokenA), MASTER_TOKEN, userIdTokenA, CRYPTO_CONTEXT);

    EXPECT_EQ(*serviceTokenA, *serviceTokenA);
    EXPECT_EQ(serviceTokenA->uniqueKey(), serviceTokenA->uniqueKey());

    EXPECT_NE(*serviceTokenA, *serviceTokenB);
    EXPECT_NE(*serviceTokenB, *serviceTokenA);
    EXPECT_NE(serviceTokenA->uniqueKey(), serviceTokenB->uniqueKey());

    EXPECT_EQ(*serviceTokenA, *serviceTokenA2);
    EXPECT_EQ(*serviceTokenA2, *serviceTokenA);
    EXPECT_EQ(serviceTokenA->uniqueKey(), serviceTokenA2->uniqueKey());
}

}}} // namespace netflix::msl::tokens
