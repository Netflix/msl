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
#include <gmock/gmock.h>
#include <tokens/MasterToken.h>
#include <crypto/JcaAlgorithm.h>
#include <crypto/Key.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslException.h>
#include <MslInternalException.h>
#include <io/MslEncoderUtils.h>
#include <util/Base64.h>

#include "../util/MockMslContext.h"
#include "../util/MslTestUtils.h"

using namespace std;
using namespace testing;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::crypto;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace tokens {

namespace {

/** Milliseconds per second. */
const int64_t MILLISECONDS_PER_SECOND = 1000;

/** Key token data. */
const string KEY_TOKENDATA = "tokendata";
/** Key signature. */
const string KEY_SIGNATURE = "signature";

// tokendata
/** Key renewal window timestamp. */
const string KEY_RENEWAL_WINDOW = "renewalwindow";
/** Key expiration timestamp. */
const string KEY_EXPIRATION = "expiration";
/** Key sequence number. */
const string KEY_SEQUENCE_NUMBER = "sequencenumber";
/** Key serial number. */
const string KEY_SERIAL_NUMBER = "serialnumber";
/** Key session data. */
const string KEY_SESSIONDATA = "sessiondata";

// sessiondata
/** Key issuer data. */
const string KEY_ISSUER_DATA = "issuerdata";
/** Key identity. */
const string KEY_IDENTITY = "identity";
/** Key symmetric encryption key. */
const string KEY_ENCRYPTION_KEY = "encryptionkey";
/** Key encryption algorithm. */
const string KEY_ENCRYPTION_ALGORITHM = "encryptionalgorithm";
/** Key symmetric HMAC key. */
const string KEY_HMAC_KEY = "hmackey";
/** Key signature key. */
const string KEY_SIGNATURE_KEY = "signaturekey";
/** Key signature algorithm. */
const string KEY_SIGNATURE_ALGORITHM = "signaturealgorithm";

const int64_t SEQUENCE_NUMBER = 1;
const int64_t SERIAL_NUMBER = 42;

const string PSK_ESN = "PSK-ESN";
/** PSK Kpe. */
const string PSK_KPE_B64 = "kzWYEtKSsPI8dOW5YyoILQ==";
/** PSK Kph. */
const string PSK_KPH_B64 = "VhxNUK7bYIcCV4wLE2YK90do1X3XqhPeMwwllmNh8Jw=";

const string IDENTITY = PSK_ESN;

int64_t incrementSequenceNumber(int64_t seqNo, int64_t amount) {
    if (seqNo - MslConstants::MAX_LONG_VALUE + amount <= 0)
        return seqNo + amount;
    return seqNo - MslConstants::MAX_LONG_VALUE - 1 + amount;
}

int64_t decrementSequenceNumber(int64_t seqNo, int64_t amount) {
    if (seqNo - amount >= 0)
        return seqNo - amount;
    return MslConstants::MAX_LONG_VALUE - amount - 1 + seqNo;
}

} // namespace anonymous

class MasterTokenTest : public ::testing::Test
{
public:
    MasterTokenTest()
    : ENCODER_FORMAT(MslEncoderFormat::JSON)
    , RENEWAL_WINDOW(make_shared<Date>(Date::now()->getTime() + 60000))
    , EXPIRATION(make_shared<Date>(Date::now()->getTime() + 120000))
    , ENCRYPTION_KEY(SecretKey(util::Base64::decode(PSK_KPE_B64), crypto::JcaAlgorithm::AES))
    , SIGNATURE_KEY(SecretKey(util::Base64::decode(PSK_KPH_B64), crypto::JcaAlgorithm::HMAC_SHA256))
    , NULL_KEY(SecretKey())
    , ctx(make_shared<MockMslContext >(EntityAuthenticationScheme::PSK, false))
    , encoder(ctx->getMslEncoderFactory())
    {
        const string objstr = "{ \"issuerid\" : 17 }";
        shared_ptr<ByteArray> objba = make_shared<ByteArray>(objstr.begin(), objstr.end());
        ISSUER_DATA = encoder->parseObject(objba);
    }
protected:
    const MslEncoderFormat ENCODER_FORMAT;
    shared_ptr<Date> RENEWAL_WINDOW;
    shared_ptr<Date> EXPIRATION;
    const SecretKey ENCRYPTION_KEY;
    const SecretKey SIGNATURE_KEY;
    const SecretKey NULL_KEY;
    shared_ptr<MslContext> ctx;
    shared_ptr<MslEncoderFactory> encoder;
    shared_ptr<MslObject> ISSUER_DATA;
};

TEST_F(MasterTokenTest, ctors)
{
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
        SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    EXPECT_TRUE(masterToken->isDecrypted());
    EXPECT_TRUE(masterToken->isVerified());
    EXPECT_FALSE(masterToken->isRenewable());
    EXPECT_FALSE(masterToken->isExpired());
    EXPECT_FALSE(masterToken->isNewerThan(masterToken));
    EXPECT_EQ(*ENCRYPTION_KEY.getEncoded(), *masterToken->getEncryptionKey().getEncoded());
    EXPECT_EQ(EXPIRATION->getTime() / MILLISECONDS_PER_SECOND, masterToken->getExpiration()->getTime() / MILLISECONDS_PER_SECOND);
    EXPECT_EQ(*SIGNATURE_KEY.getEncoded(), *masterToken->getSignatureKey().getEncoded());
    EXPECT_EQ(IDENTITY, masterToken->getIdentity());
    EXPECT_EQ(ISSUER_DATA, masterToken->getIssuerData());
    EXPECT_EQ(RENEWAL_WINDOW->getTime() / MILLISECONDS_PER_SECOND, masterToken->getRenewalWindow()->getTime() / MILLISECONDS_PER_SECOND);
    EXPECT_EQ(SEQUENCE_NUMBER, masterToken->getSequenceNumber());
    EXPECT_EQ(SERIAL_NUMBER, masterToken->getSerialNumber());
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(encode);

    shared_ptr<MslObject> mo = encoder->parseObject(encode);
    shared_ptr<MasterToken> moMasterToken = make_shared<MasterToken>(ctx, mo);
    EXPECT_EQ(masterToken->isDecrypted(), moMasterToken->isDecrypted());
    EXPECT_EQ(masterToken->isVerified(), moMasterToken->isVerified());
    EXPECT_EQ(masterToken->isRenewable(), moMasterToken->isRenewable());
    EXPECT_EQ(masterToken->isExpired(), moMasterToken->isExpired());
    EXPECT_FALSE(moMasterToken->isNewerThan(masterToken));
    EXPECT_FALSE(masterToken->isNewerThan(moMasterToken));
    EXPECT_EQ(*masterToken->getEncryptionKey().getEncoded(), *moMasterToken->getEncryptionKey().getEncoded());
    EXPECT_EQ(masterToken->getExpiration()->getTime() / MILLISECONDS_PER_SECOND, moMasterToken->getExpiration()->getTime() / MILLISECONDS_PER_SECOND);
    EXPECT_EQ(*masterToken->getSignatureKey().getEncoded(), *moMasterToken->getSignatureKey().getEncoded());
    EXPECT_EQ(masterToken->getIdentity(), moMasterToken->getIdentity());
    EXPECT_EQ(*masterToken->getIssuerData(), *moMasterToken->getIssuerData());
    EXPECT_EQ(masterToken->getRenewalWindow()->getTime() / MILLISECONDS_PER_SECOND, moMasterToken->getRenewalWindow()->getTime() / MILLISECONDS_PER_SECOND);
    EXPECT_EQ(masterToken->getSequenceNumber(), moMasterToken->getSequenceNumber());
    EXPECT_EQ(masterToken->getSerialNumber(), moMasterToken->getSerialNumber());
    shared_ptr<ByteArray> moEncode = moMasterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_EQ(*encode, *moEncode);
}

TEST_F(MasterTokenTest, negativeSequenceNumberCtor)
{
    const int64_t sequenceNumber = -1;
    EXPECT_THROW(
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumber,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY),
        MslInternalException
    );
}


TEST_F(MasterTokenTest, tooLargeSequenceNumberCtor)
{
    const int64_t sequenceNumber = MslConstants::MAX_LONG_VALUE + 1;
    EXPECT_THROW(
        MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumber,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY),
        MslInternalException
    );
}

TEST_F(MasterTokenTest, negativeSerialNumberCtor)
{
    const int64_t serialNumber = -1;
    EXPECT_THROW(
        MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            serialNumber, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY),
        MslInternalException
    );
}

TEST_F(MasterTokenTest, tooLargeSerialNumberCtor)
{
    const int64_t serialNumber = MslConstants::MAX_LONG_VALUE + 1;
    EXPECT_THROW(
        MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
                serialNumber, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY),
        MslInternalException
    );
}

TEST_F(MasterTokenTest, inconsistentExpiration)
{
    shared_ptr<Date> renewalWindow = Date::now();
    shared_ptr<Date> expiration = make_shared<Date>(renewalWindow->getTime() - 1);
    EXPECT_TRUE(expiration->before(renewalWindow));
    EXPECT_THROW(
        MasterToken(ctx, renewalWindow, expiration, SEQUENCE_NUMBER,
                SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY),
        MslInternalException
    );
}

TEST_F(MasterTokenTest, inconsistentExpirationParse)
{
//    thrown.expect(MslException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_EXPIRES_BEFORE_RENEWAL);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    tokendataMo->put<int64_t>(KEY_EXPIRATION, Date::now()->getTime() / MILLISECONDS_PER_SECOND - 1);
    tokendataMo->put<int64_t>(KEY_RENEWAL_WINDOW, Date::now()->getTime() / MILLISECONDS_PER_SECOND);
    mo->put<shared_ptr<ByteArray>>(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_EXPIRES_BEFORE_RENEWAL, e.getError());
    }
}

TEST_F(MasterTokenTest, nullIssuerData)
{
    shared_ptr<MslObject> emptyIssuerData = encoder->createObject();
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
        SERIAL_NUMBER, emptyIssuerData, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    EXPECT_TRUE(MslEncoderUtils::equalObjects(emptyIssuerData, masterToken->getIssuerData()));

    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<MasterToken> moMasterToken = make_shared<MasterToken>(ctx, mo);
    EXPECT_TRUE(MslEncoderUtils::equalObjects(emptyIssuerData, moMasterToken->getIssuerData()));
}

TEST_F(MasterTokenTest, missingTokendata)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    EXPECT_FALSE(mo->remove(KEY_TOKENDATA).isNull());

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, invalidTokendata)
{
//@Test(expected = MslEncodingException.class)
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    ++(*tokendata)[0];
    mo->put(KEY_TOKENDATA, tokendata);

    EXPECT_THROW(MasterToken mt(ctx, mo), MslEncodingException);
}

TEST_F(MasterTokenTest, missingSignature)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    EXPECT_FALSE(mo->remove(KEY_SIGNATURE).isNull());

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, missingRenewalWindow)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    EXPECT_FALSE(tokendataMo->remove(KEY_RENEWAL_WINDOW).isNull());
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, invalidRenewalWindow)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    tokendataMo->put<string>(KEY_RENEWAL_WINDOW, "x");
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, missingExpiration)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    EXPECT_FALSE(tokendataMo->remove(KEY_EXPIRATION).isNull());
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, invalidExpiration)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    tokendataMo->put<string>(KEY_EXPIRATION, "x");
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, missingSequenceNumber)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    EXPECT_FALSE(tokendataMo->remove(KEY_SEQUENCE_NUMBER).isNull());
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, invalidSequenceNumber)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    tokendataMo->put<string>(KEY_SEQUENCE_NUMBER, "x");
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, negativeSequenceNumber)
{
//    thrown.expect(MslException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    tokendataMo->put<int64_t>(KEY_SEQUENCE_NUMBER, -1);
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE, e.getError());
    }
}

TEST_F(MasterTokenTest, tooLargeSequenceNumber)
{
//    thrown.expect(MslException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    tokendataMo->put<int64_t>(KEY_SEQUENCE_NUMBER, MslConstants::MAX_LONG_VALUE + 1);
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE, e.getError());
    }
}

TEST_F(MasterTokenTest, missingSerialNumber)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    EXPECT_FALSE(tokendataMo->remove(KEY_SERIAL_NUMBER).isNull());
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, invalidSerialNumber)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    tokendataMo->put<string>(KEY_SERIAL_NUMBER, "x");
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, negativeSerialNumber)
{
//    thrown.expect(MslException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    tokendataMo->put(KEY_SERIAL_NUMBER, -1);
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, e.getError());
    }
}

TEST_F(MasterTokenTest, tooLargeSerialNumber)
{
//    thrown.expect(MslException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    tokendataMo->put<int64_t>(KEY_SERIAL_NUMBER, MslConstants::MAX_LONG_VALUE + 1);
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, e.getError());
    }
}

TEST_F(MasterTokenTest, missingSessiondata)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    EXPECT_FALSE(tokendataMo->remove(KEY_SESSIONDATA).isNull());
    mo->put(KEY_TOKENDATA, encoder->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, invalidSessiondata)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    tokendataMo->put<string>(KEY_SESSIONDATA, "x");

    shared_ptr<ICryptoContext> cryptoContext = ctx->getMslCryptoContext();
    shared_ptr<ByteArray> modifiedTokendata = encoder->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder, ENCODER_FORMAT);
    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, emptySessiondata)
{
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);

    shared_ptr<ICryptoContext> cryptoContext = ctx->getMslCryptoContext();
    shared_ptr<ByteArray> ciphertext = make_shared<ByteArray>();
    tokendataMo->put(KEY_SESSIONDATA, ciphertext);
    shared_ptr<ByteArray> modifiedTokendata = encoder->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder, ENCODER_FORMAT);

    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_SESSIONDATA_MISSING, e.getError());
    }
}

TEST_F(MasterTokenTest, corruptSessiondata)
{
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    // This is testing session data that is verified but corrupt.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    shared_ptr<ByteArray> sessiondata = tokendataMo->getBytes(KEY_SESSIONDATA);
    ++(*sessiondata)[sessiondata->size()-1];
    tokendataMo->put(KEY_SESSIONDATA, sessiondata);

    shared_ptr<ICryptoContext> cryptoContext = ctx->getMslCryptoContext();
    shared_ptr<ByteArray> modifiedTokendata = encoder->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder, ENCODER_FORMAT);

    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    EXPECT_THROW(MasterToken(ctx, mo), MslCryptoException);
}

TEST_F(MasterTokenTest, notVerified)
{
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ByteArray> signature = mo->getBytes(KEY_SIGNATURE);
    assert(signature->size());
    ++(*signature)[0];
    mo->put(KEY_SIGNATURE, signature);

    shared_ptr<MasterToken> moMasterToken = make_shared<MasterToken>(ctx, mo);
    EXPECT_FALSE(moMasterToken->isDecrypted());
    EXPECT_FALSE(moMasterToken->isVerified());
    EXPECT_TRUE(moMasterToken->isRenewable());
    EXPECT_FALSE(moMasterToken->isExpired());
    EXPECT_FALSE(moMasterToken->isNewerThan(masterToken));
    EXPECT_FALSE(masterToken->isNewerThan(moMasterToken));
    EXPECT_TRUE(moMasterToken->getEncryptionKey().isNull());
    EXPECT_EQ(masterToken->getExpiration()->getTime(), moMasterToken->getExpiration()->getTime());
    EXPECT_TRUE(moMasterToken->getSignatureKey().isNull());
    EXPECT_TRUE(moMasterToken->getIdentity().empty());
    EXPECT_TRUE(MslEncoderUtils::equalObjects(ISSUER_DATA, masterToken->getIssuerData()));
    EXPECT_EQ(masterToken->getRenewalWindow()->getTime(), moMasterToken->getRenewalWindow()->getTime());
    EXPECT_EQ(masterToken->getSequenceNumber(), moMasterToken->getSequenceNumber());
    EXPECT_EQ(masterToken->getSerialNumber(), moMasterToken->getSerialNumber());
    shared_ptr<ByteArray> moEncode = moMasterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_NE(*encode, *moEncode);
}

TEST_F(MasterTokenTest, invalidIssuerData)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ICryptoContext> cryptoContext = ctx->getMslCryptoContext();

    // Before modifying the session data we need to decrypt it.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    shared_ptr<ByteArray> ciphertext = tokendataMo->getBytes(KEY_SESSIONDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> sessiondataMo = encoder->parseObject(plaintext);

    // After modifying the session data we need to encrypt it.
    sessiondataMo->put<string>(KEY_ISSUER_DATA, "x");
    shared_ptr<ByteArray> sessiondata = cryptoContext->encrypt(encoder->encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
    tokendataMo->put(KEY_SESSIONDATA, sessiondata);

    // The tokendata must be signed otherwise the session data will not be
    // processed.
    shared_ptr<ByteArray> modifiedTokendata = encoder->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder, ENCODER_FORMAT);

    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_SESSIONDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, missingIdentity)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ICryptoContext> cryptoContext = ctx->getMslCryptoContext();

    // Before modifying the session data we need to decrypt it.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    shared_ptr<ByteArray> ciphertext = tokendataMo->getBytes(KEY_SESSIONDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> sessiondataMo = encoder->parseObject(plaintext);

    // After modifying the session data we need to encrypt it.
    EXPECT_FALSE(sessiondataMo->remove(KEY_IDENTITY).isNull());
    shared_ptr<ByteArray> sessiondata = cryptoContext->encrypt(encoder->encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
    tokendataMo->put(KEY_SESSIONDATA, sessiondata);

    // The tokendata must be signed otherwise the session data will not be
    // processed.
    shared_ptr<ByteArray> modifiedTokendata = encoder->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder, ENCODER_FORMAT);

    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_SESSIONDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, missingEncryptionKey)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ICryptoContext> cryptoContext = ctx->getMslCryptoContext();

    // Before modifying the session data we need to decrypt it.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    shared_ptr<ByteArray> ciphertext = tokendataMo->getBytes(KEY_SESSIONDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> sessiondataMo = encoder->parseObject(plaintext);

    // After modifying the session data we need to encrypt it.
    EXPECT_FALSE(sessiondataMo->remove(KEY_ENCRYPTION_KEY).isNull());
    shared_ptr<ByteArray> sessiondata = cryptoContext->encrypt(encoder->encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
    tokendataMo->put(KEY_SESSIONDATA, sessiondata);

    // The tokendata must be signed otherwise the session data will not be
    // processed.
    shared_ptr<ByteArray> modifiedTokendata = encoder->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder, ENCODER_FORMAT);

    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_SESSIONDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, invalidEncryptionKey)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_KEY_CREATION_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ICryptoContext> cryptoContext = ctx->getMslCryptoContext();

    // Before modifying the session data we need to decrypt it.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    shared_ptr<ByteArray> ciphertext = tokendataMo->getBytes(KEY_SESSIONDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> sessiondataMo = encoder->parseObject(plaintext);

    // After modifying the session data we need to encrypt it.
    sessiondataMo->put<string>(KEY_ENCRYPTION_KEY, "");
    shared_ptr<ByteArray> sessiondata = cryptoContext->encrypt(encoder->encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
    tokendataMo->put(KEY_SESSIONDATA, sessiondata);

    // The tokendata must be signed otherwise the session data will not be
    // processed.
    shared_ptr<ByteArray> modifiedTokendata = encoder->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder, ENCODER_FORMAT);

    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_KEY_CREATION_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, missingEncryptionAlgorithm)
{
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ICryptoContext> cryptoContext = ctx->getMslCryptoContext();

    // Before modifying the session data we need to decrypt it.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    shared_ptr<ByteArray> ciphertext = tokendataMo->getBytes(KEY_SESSIONDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> sessiondataMo = encoder->parseObject(plaintext);

    // After modifying the session data we need to encrypt it.
    EXPECT_FALSE(sessiondataMo->remove(KEY_ENCRYPTION_ALGORITHM).isNull());
    shared_ptr<ByteArray> sessiondata = cryptoContext->encrypt(encoder->encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
    tokendataMo->put(KEY_SESSIONDATA, sessiondata);

    // The tokendata must be signed otherwise the session data will not be
    // processed.
    shared_ptr<ByteArray> modifiedTokendata = encoder->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder, ENCODER_FORMAT);

    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    // Confirm default algorithm.
    shared_ptr<MasterToken> moMasterToken = make_shared<MasterToken>(ctx, mo);
    const SecretKey moEncryptionKey = moMasterToken->getEncryptionKey();
    EXPECT_EQ(JcaAlgorithm::AES, moEncryptionKey.getAlgorithm());
}

TEST_F(MasterTokenTest, invalidEncryptionAlgorithm)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError.UNIDENTIFIED_ALGORITHM);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ICryptoContext> cryptoContext = ctx->getMslCryptoContext();

    // Before modifying the session data we need to decrypt it.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    shared_ptr<ByteArray> ciphertext = tokendataMo->getBytes(KEY_SESSIONDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> sessiondataMo = encoder->parseObject(plaintext);

    // After modifying the session data we need to encrypt it.
    sessiondataMo->put<string>(KEY_ENCRYPTION_ALGORITHM, "x");
    shared_ptr<ByteArray> sessiondata = cryptoContext->encrypt(encoder->encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
    tokendataMo->put(KEY_SESSIONDATA, sessiondata);

    // The tokendata must be signed otherwise the session data will not be
    // processed.
    shared_ptr<ByteArray> modifiedTokendata = encoder->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder, ENCODER_FORMAT);

    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::UNIDENTIFIED_ALGORITHM, e.getError());
    }
}

TEST_F(MasterTokenTest, missingHmacKey)
{
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ICryptoContext> cryptoContext = ctx->getMslCryptoContext();

    // Before modifying the session data we need to decrypt it.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    shared_ptr<ByteArray> ciphertext = tokendataMo->getBytes(KEY_SESSIONDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> sessiondataMo = encoder->parseObject(plaintext);

    // After modifying the session data we need to encrypt it.
    EXPECT_FALSE(sessiondataMo->remove(KEY_HMAC_KEY).isNull());
    shared_ptr<ByteArray> sessiondata = cryptoContext->encrypt(encoder->encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
    tokendataMo->put(KEY_SESSIONDATA, sessiondata);

    // The tokendata must be signed otherwise the session data will not be
    // processed.
    shared_ptr<ByteArray> modifiedTokendata = encoder->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder, ENCODER_FORMAT);

    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    // Confirm signature key.
    shared_ptr<MasterToken> moMasterToken = make_shared<MasterToken>(ctx, mo);
    const SecretKey moSignatureKey = moMasterToken->getSignatureKey();
    EXPECT_EQ(*masterToken->getSignatureKey().getEncoded(), *moSignatureKey.getEncoded());
}

TEST_F(MasterTokenTest, missingSignatureKey)
{
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ICryptoContext> cryptoContext = ctx->getMslCryptoContext();

    // Before modifying the session data we need to decrypt it.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    shared_ptr<ByteArray> ciphertext = tokendataMo->getBytes(KEY_SESSIONDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> sessiondataMo = encoder->parseObject(plaintext);

    // After modifying the session data we need to encrypt it.
    EXPECT_FALSE(sessiondataMo->remove(KEY_SIGNATURE_KEY).isNull());
    shared_ptr<ByteArray> sessiondata = cryptoContext->encrypt(encoder->encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
    tokendataMo->put(KEY_SESSIONDATA, sessiondata);

    // The tokendata must be signed otherwise the session data will not be
    // processed.
    shared_ptr<ByteArray> modifiedTokendata = encoder->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder, ENCODER_FORMAT);

    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    // Confirm signature key.
    shared_ptr<MasterToken> moMasterToken = make_shared<MasterToken>(ctx, mo);
    const SecretKey moSignatureKey = moMasterToken->getSignatureKey();
    EXPECT_EQ(*masterToken->getSignatureKey().getEncoded(), *moSignatureKey.getEncoded());
}

TEST_F(MasterTokenTest, missingSignatureAlgorithm)
{
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ICryptoContext> cryptoContext = ctx->getMslCryptoContext();

    // Before modifying the session data we need to decrypt it.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    shared_ptr<ByteArray> ciphertext = tokendataMo->getBytes(KEY_SESSIONDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> sessiondataMo = encoder->parseObject(plaintext);

    // After modifying the session data we need to encrypt it.
    EXPECT_FALSE(sessiondataMo->remove(KEY_SIGNATURE_ALGORITHM).isNull());
    shared_ptr<ByteArray> sessiondata = cryptoContext->encrypt(encoder->encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
    tokendataMo->put(KEY_SESSIONDATA, sessiondata);

    // The tokendata must be signed otherwise the session data will not be
    // processed.
    shared_ptr<ByteArray> modifiedTokendata = encoder->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder, ENCODER_FORMAT);

    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    // Confirm default algorithm.
    shared_ptr<MasterToken> moMasterToken = make_shared<MasterToken>(ctx, mo);
    const SecretKey moSignatureKey = moMasterToken->getSignatureKey();
    EXPECT_EQ(JcaAlgorithm::HMAC_SHA256, moSignatureKey.getAlgorithm());
}

TEST_F(MasterTokenTest, invalidSignatureAlgorithm)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError.UNIDENTIFIED_ALGORITHM);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ICryptoContext> cryptoContext = ctx->getMslCryptoContext();

    // Before modifying the session data we need to decrypt it.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    shared_ptr<ByteArray> ciphertext = tokendataMo->getBytes(KEY_SESSIONDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> sessiondataMo = encoder->parseObject(plaintext);

    // After modifying the session data we need to encrypt it.
    sessiondataMo->put<string>(KEY_SIGNATURE_ALGORITHM, "x");
    shared_ptr<ByteArray> sessiondata = cryptoContext->encrypt(encoder->encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
    tokendataMo->put(KEY_SESSIONDATA, sessiondata);

    // The tokendata must be signed otherwise the session data will not be
    // processed.
    shared_ptr<ByteArray> modifiedTokendata = encoder->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder, ENCODER_FORMAT);

    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::UNIDENTIFIED_ALGORITHM, e.getError());
    }
}

TEST_F(MasterTokenTest, missingHmacAndSignatureKey)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<ByteArray> encode = masterToken->toMslEncoding(encoder, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder->parseObject(encode);

    shared_ptr<ICryptoContext> cryptoContext = ctx->getMslCryptoContext();

    // Before modifying the session data we need to decrypt it.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    shared_ptr<ByteArray> ciphertext = tokendataMo->getBytes(KEY_SESSIONDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> sessiondataMo = encoder->parseObject(plaintext);

    // After modifying the session data we need to encrypt it.
    EXPECT_FALSE(sessiondataMo->remove(KEY_HMAC_KEY).isNull());
    EXPECT_FALSE(sessiondataMo->remove(KEY_SIGNATURE_KEY).isNull());
    shared_ptr<ByteArray> sessiondata = cryptoContext->encrypt(encoder->encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
    tokendataMo->put(KEY_SESSIONDATA, sessiondata);

    // The tokendata must be signed otherwise the session data will not be
    // processed.
    shared_ptr<ByteArray> modifiedTokendata = encoder->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder, ENCODER_FORMAT);

    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_SESSIONDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, invalidHmacAndSignatureKey)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError.MASTERTOKEN_KEY_CREATION_ERROR);

    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, masterToken);

    shared_ptr<ICryptoContext> cryptoContext = ctx->getMslCryptoContext();

    // Before modifying the session data we need to decrypt it.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder->parseObject(tokendata);
    shared_ptr<ByteArray> ciphertext = tokendataMo->getBytes(KEY_SESSIONDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> sessiondataMo = encoder->parseObject(plaintext);

    // After modifying the session data we need to encrypt it.
    sessiondataMo->put<string>(KEY_HMAC_KEY, "");
    sessiondataMo->put<string>(KEY_SIGNATURE_KEY, "");
    shared_ptr<ByteArray> sessiondata = cryptoContext->encrypt(encoder->encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
    tokendataMo->put(KEY_SESSIONDATA, sessiondata);

    // The tokendata must be signed otherwise the session data will not be
    // processed.
    shared_ptr<ByteArray> modifiedTokendata = encoder->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder, ENCODER_FORMAT);

    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    try {
        shared_ptr<MasterToken> mt = make_shared<MasterToken>(ctx, mo);
        ADD_FAILURE() << "should have thrown";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::MASTERTOKEN_KEY_CREATION_ERROR, e.getError());
    }
}

TEST_F(MasterTokenTest, isRenewable)
{
    shared_ptr<Date> renewalWindow = Date::now();
    shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 1000);
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, renewalWindow, expiration, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);

    shared_ptr<Date> now = Date::now();
    EXPECT_TRUE(masterToken->isRenewable());
    EXPECT_TRUE(masterToken->isRenewable(now));
    EXPECT_FALSE(masterToken->isExpired());
    EXPECT_FALSE(masterToken->isExpired(now));

    shared_ptr<Date> before = make_shared<Date>(Date::now()->getTime() - 1000);
    EXPECT_FALSE(masterToken->isRenewable(before));
    EXPECT_FALSE(masterToken->isExpired(before));

    shared_ptr<Date> after = make_shared<Date>(expiration->getTime() + 1000);
    EXPECT_TRUE(masterToken->isRenewable(after));
    EXPECT_TRUE(masterToken->isExpired(after));
}

TEST_F(MasterTokenTest, isExpired)
{
    shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 1000);
    shared_ptr<Date> expiration = Date::now();
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, renewalWindow, expiration, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);

    shared_ptr<Date> now = Date::now();
    EXPECT_TRUE(masterToken->isRenewable());
    EXPECT_TRUE(masterToken->isRenewable(now));
    EXPECT_TRUE(masterToken->isExpired());
    EXPECT_TRUE(masterToken->isExpired(now));

    shared_ptr<Date> before = make_shared<Date>(renewalWindow->getTime() - 1000);
    EXPECT_FALSE(masterToken->isRenewable(before));
    EXPECT_FALSE(masterToken->isExpired(before));

    shared_ptr<Date> after = make_shared<Date>(expiration->getTime() + 1000);
    EXPECT_TRUE(masterToken->isRenewable(after));
    EXPECT_TRUE(masterToken->isExpired(after));
}

TEST_F(MasterTokenTest, notRenewableOrExpired)
{
    shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() + 1000);
    shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 2000);
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, renewalWindow, expiration, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);

    shared_ptr<Date> now = Date::now();
    EXPECT_FALSE(masterToken->isRenewable());
    EXPECT_FALSE(masterToken->isRenewable(now));
    EXPECT_FALSE(masterToken->isExpired());
    EXPECT_FALSE(masterToken->isExpired(now));

    shared_ptr<Date> before = make_shared<Date>(renewalWindow->getTime() - 1000);
    EXPECT_FALSE(masterToken->isRenewable(before));
    EXPECT_FALSE(masterToken->isExpired(before));

    shared_ptr<Date> after = make_shared<Date>(expiration->getTime() + 1000);
    EXPECT_TRUE(masterToken->isRenewable(after));
    EXPECT_TRUE(masterToken->isExpired(after));
}

TEST_F(MasterTokenTest, isNewerThanSequenceNumbers)
{
    const int64_t sequenceNumberA = 1;
    const int64_t sequenceNumberB = 2;
    shared_ptr<MasterToken> masterTokenA = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberA,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<MasterToken> masterTokenB = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberB,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);

    EXPECT_TRUE(masterTokenB->isNewerThan(masterTokenA));
    EXPECT_FALSE(masterTokenA->isNewerThan(masterTokenB));
    EXPECT_FALSE(masterTokenA->isNewerThan(masterTokenA));
}

TEST_F(MasterTokenTest, isNewerThanSequenceNumbersWrapAround)
{
    // Anything within 128 is newer.
    for (int64_t seqNo = MslConstants::MAX_LONG_VALUE - 127;
         seqNo <= MslConstants::MAX_LONG_VALUE && seqNo != 0;
         seqNo = incrementSequenceNumber(seqNo, 1ll))
    {
        const int64_t minus1 = decrementSequenceNumber(seqNo, 1ll);
        const int64_t plus1 = incrementSequenceNumber(seqNo, 1ll);
        const int64_t plus127 = incrementSequenceNumber(seqNo, 127ll);
        const int64_t plus128 = incrementSequenceNumber(seqNo, 128ll);

        shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, seqNo, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        shared_ptr<MasterToken> minus1MasterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, minus1, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        shared_ptr<MasterToken> plus1MasterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, plus1, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        shared_ptr<MasterToken> plus127MasterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, plus127, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        shared_ptr<MasterToken> plus128MasterToken = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, plus128, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);

        EXPECT_FALSE(minus1MasterToken->isNewerThan(masterToken)) << "seqNo = " << seqNo;
        EXPECT_TRUE(masterToken->isNewerThan(minus1MasterToken)) << "seqNo = " << seqNo;
        EXPECT_TRUE(plus1MasterToken->isNewerThan(masterToken)) << "seqNo = " << seqNo;
        EXPECT_FALSE(masterToken->isNewerThan(plus1MasterToken)) << "seqNo = " << seqNo;
        EXPECT_TRUE(plus127MasterToken->isNewerThan(masterToken)) << "seqNo = " << seqNo;
        EXPECT_FALSE(masterToken->isNewerThan(plus127MasterToken)) << "seqNo = " << seqNo;
        EXPECT_FALSE(plus128MasterToken->isNewerThan(masterToken)) << "seqNo = " << seqNo;
        EXPECT_TRUE(masterToken->isNewerThan(plus128MasterToken)) << "seqNo = " << seqNo;
    }
}

TEST_F(MasterTokenTest, isNewerThanExpiration)
{
    shared_ptr<Date> expirationA = make_shared<Date>(EXPIRATION->getTime());
    shared_ptr<Date> expirationB = make_shared<Date>(EXPIRATION->getTime() + 10000);
    shared_ptr<MasterToken> masterTokenA = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, expirationA, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<MasterToken> masterTokenB = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, expirationB, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);

    EXPECT_TRUE(masterTokenB->isNewerThan(masterTokenA));
    EXPECT_FALSE(masterTokenA->isNewerThan(masterTokenB));
    EXPECT_FALSE(masterTokenA->isNewerThan(masterTokenA));
}

TEST_F(MasterTokenTest, isNewerSerialNumber)
{
    const int64_t serialNumberA = 1;
    const int64_t serialNumberB = 2;
    const int64_t sequenceNumberA = 1;
    const int64_t sequenceNumberB = 2;
    shared_ptr<MasterToken> masterTokenA = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberA, serialNumberA, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<MasterToken> masterTokenB = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberB, serialNumberB, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);

    EXPECT_TRUE(masterTokenB->isNewerThan(masterTokenA));
    EXPECT_FALSE(masterTokenA->isNewerThan(masterTokenB));
}

TEST_F(MasterTokenTest, equalsTrustedUntrusted)
{
    shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() + 1000);
    shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 2000);
    const string identity = PSK_ESN;
    const SecretKey encryptionKey = ENCRYPTION_KEY;
    const SecretKey hmacKey = SIGNATURE_KEY;
    shared_ptr<MasterToken> masterToken = make_shared<MasterToken>(ctx, renewalWindow, expiration, 1ll, 1ll, make_shared<MslObject>(), identity, ENCRYPTION_KEY, SIGNATURE_KEY);

    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, masterToken);
    shared_ptr<ByteArray> signature = mo->getBytes("signature");
    ++(*signature)[1];
    mo->put("signature", signature);
    shared_ptr<MasterToken> untrustedMasterToken = make_shared<MasterToken>(ctx, mo);

    EXPECT_EQ(*masterToken, *untrustedMasterToken);
}

TEST_F(MasterTokenTest, equalsSerialNumber)
{
    const int64_t serialNumberA = 1ll;
    const int64_t serialNumberB = 2ll;
    shared_ptr<MasterToken> masterTokenA = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            serialNumberA, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<MasterToken> masterTokenB = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER,
            serialNumberB, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<MasterToken> masterTokenA2 = make_shared<MasterToken>(ctx, MslTestUtils::toMslObject(encoder, masterTokenA));

    EXPECT_EQ(*masterTokenA, *masterTokenA);
    EXPECT_EQ(masterTokenA->uniqueKey(), masterTokenA->uniqueKey());

    EXPECT_NE(*masterTokenA, *masterTokenB);
    EXPECT_NE(*masterTokenB, *masterTokenA);
    EXPECT_NE(masterTokenA->uniqueKey(), masterTokenB->uniqueKey());

    EXPECT_EQ(*masterTokenA, *masterTokenA2);
    EXPECT_EQ(*masterTokenA2, *masterTokenA);
    EXPECT_EQ(masterTokenA->uniqueKey(), masterTokenA2->uniqueKey());
}

TEST_F(MasterTokenTest, equalsSequenceNumber)
{
    const int64_t sequenceNumberA = 1;
    const int64_t sequenceNumberB = 2;
    shared_ptr<MasterToken> masterTokenA = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberA,
             SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<MasterToken> masterTokenB = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberB,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<MasterToken> masterTokenA2 = make_shared<MasterToken>(ctx, MslTestUtils::toMslObject(encoder, masterTokenA));

    EXPECT_EQ(*masterTokenA, *masterTokenA);
    EXPECT_EQ(masterTokenA->uniqueKey(), masterTokenA->uniqueKey());

    EXPECT_NE(*masterTokenA, *masterTokenB);
    EXPECT_NE(*masterTokenB, *masterTokenA);
    EXPECT_NE(masterTokenA->uniqueKey(), masterTokenB->uniqueKey());

    EXPECT_EQ(*masterTokenA, *masterTokenA2);
    EXPECT_EQ(*masterTokenA2, *masterTokenA);
    EXPECT_EQ(masterTokenA->uniqueKey(), masterTokenA2->uniqueKey());
}

TEST_F(MasterTokenTest, equalsExpiration)
{
    shared_ptr<Date> expirationA = make_shared<Date>(EXPIRATION->getTime());
    shared_ptr<Date> expirationB = make_shared<Date>(EXPIRATION->getTime() + 10000);
    shared_ptr<MasterToken> masterTokenA = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, expirationA, SEQUENCE_NUMBER,
             SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<MasterToken> masterTokenB = make_shared<MasterToken>(ctx, RENEWAL_WINDOW, expirationB, SEQUENCE_NUMBER,
            SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    shared_ptr<MasterToken> masterTokenA2 = make_shared<MasterToken>(ctx, MslTestUtils::toMslObject(encoder, masterTokenA));

    EXPECT_EQ(*masterTokenA, *masterTokenA);
    EXPECT_EQ(masterTokenA->uniqueKey(), masterTokenA->uniqueKey());

    EXPECT_NE(*masterTokenA, *masterTokenB);
    EXPECT_NE(*masterTokenB, *masterTokenA);
    EXPECT_NE(masterTokenA->uniqueKey(), masterTokenB->uniqueKey());

    EXPECT_EQ(*masterTokenA, *masterTokenA2);
    EXPECT_EQ(*masterTokenA2, *masterTokenA);
    EXPECT_EQ(masterTokenA->uniqueKey(), masterTokenA2->uniqueKey());
}

}}} // namespace netflix::msl::tokens
