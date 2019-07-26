/**
 * Copyright (c) 2016-2018 Netflix, Inc.  All rights reserved.
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

#include <crypto/ICryptoContext.h>
#include <gtest/gtest.h>
#include <msg/ErrorHeader.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <Date.h>
#include <Macros.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <MslMessageException.h>
#include <stdint.h>
#include <unistd.h>
#include <map>
#include <memory>
#include <string>

#include "../util/MockMslContext.h"
#include "../util/MslTestUtils.h"

using namespace std;
using namespace testing;
using namespace netflix::msl;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace msg {

namespace {

/** Milliseconds per second. */
const int64_t MILLISECONDS_PER_SECOND = 1000;

/** Key entity authentication data. */
const string KEY_ENTITY_AUTHENTICATION_DATA = "entityauthdata";
/** Key error data. */
const string KEY_ERRORDATA = "errordata";
/** Key error data signature. */
const string KEY_SIGNATURE = "signature";

// Message error data.
/** Key timestamp. */
const string KEY_TIMESTAMP = "timestamp";
/** Key message ID. */
const string KEY_MESSAGE_ID = "messageid";
/** Key error code. */
const string KEY_ERROR_CODE = "errorcode";
/** Key internal code. */
const string KEY_INTERNAL_CODE = "internalcode";
/** Key error message. */
const string KEY_ERROR_MESSAGE = "errormsg";
/** Key user message. */
const string KEY_USER_MESSAGE = "usermsg";

const int64_t MESSAGE_ID = 17;
const int32_t INTERNAL_CODE = 621;
const string ERROR_MSG = "Error message.";
const string USER_MSG = "User message.";

/**
 * Checks if the given timestamp is close to "now".
 *
 * @param timestamp the timestamp to compare.
 * @return true if the timestamp is about now.
 */
bool isAboutNow(shared_ptr<Date> timestamp)
{
    const int64_t now = Date::now()->getTime();
    const int64_t time = timestamp->getTime();
    return (now - 1000 <= time && time <= now + 1000);
}

/**
 * Checks if the given timestamp is close to "now".
 *
 * @param seconds the timestamp to compare in seconds since the epoch.
 * @return true if the timestamp is about now.
 */
bool isAboutNowSeconds(int64_t seconds)
{
    const int64_t now = Date::now()->getTime();
    const int64_t time = seconds * MILLISECONDS_PER_SECOND;
    return (now - 1000 <= time && time <= now + 1000);
}

} // namespace anonymous

/**
 * Error header unit tests.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class ErrorHeaderTest : public ::testing::Test
{
public:
    ErrorHeaderTest()
    : ENCODER_FORMAT(MslEncoderFormat::JSON)
    , ctx(getMslCtx())
    , encoder(ctx->getMslEncoderFactory())
    , ENTITY_AUTH_DATA(ctx->getEntityAuthenticationData(MslContext::ReauthCode::INVALID))
    , cryptoContext(ctx->getEntityAuthenticationFactory(ENTITY_AUTH_DATA->getScheme())->getCryptoContext(ctx, ENTITY_AUTH_DATA))
    , ERROR_CODE(MslConstants::ResponseCode::FAIL)
    {
    }

protected:
    /** MSL encoder format. */
    const MslEncoderFormat ENCODER_FORMAT;

    /** MSL context. */
    shared_ptr<MockMslContext> ctx;
    /** MSL encoder factory. */
    shared_ptr<MslEncoderFactory> encoder;
    shared_ptr<EntityAuthenticationData> ENTITY_AUTH_DATA;
    /** Header crypto context. */
    shared_ptr<ICryptoContext> cryptoContext;

    const MslConstants::ResponseCode ERROR_CODE;
    map<string, shared_ptr<ICryptoContext>> CRYPTO_CONTEXTS;

private:
    // Factory method for MockMslConext singleton; only need one for all tests,
    // and it is expensive
    shared_ptr<MockMslContext> getMslCtx()
    {
        static shared_ptr<MockMslContext> theInstance;
        if (!theInstance)
            theInstance = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
        return theInstance;
    }
};

TEST_F(ErrorHeaderTest, ctors)
{
    const ErrorHeader errorHeader(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    EXPECT_EQ(ENTITY_AUTH_DATA, errorHeader.getEntityAuthenticationData());
    EXPECT_EQ(ERROR_CODE, errorHeader.getErrorCode());
    EXPECT_EQ(ERROR_MSG, errorHeader.getErrorMessage());
    EXPECT_EQ(INTERNAL_CODE, errorHeader.getInternalCode());
    EXPECT_EQ(MESSAGE_ID, errorHeader.getMessageId());
    EXPECT_EQ(USER_MSG, errorHeader.getUserMessage());
    EXPECT_TRUE(isAboutNow(errorHeader.getTimestamp()));
}

TEST_F(ErrorHeaderTest, mslObject)
{
    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);

    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, errorHeader);
    shared_ptr<MslObject> entityAuthDataMo = mo->getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
    EXPECT_EQ(*MslTestUtils::toMslObject(encoder, ENTITY_AUTH_DATA), *entityAuthDataMo);
    shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_ERRORDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> errordata = encoder->parseObject(plaintext);
    shared_ptr<ByteArray> signature = mo->getBytes(KEY_SIGNATURE);
    EXPECT_TRUE(cryptoContext->verify(ciphertext, signature, encoder));

    EXPECT_EQ(MESSAGE_ID, errordata->getLong(KEY_MESSAGE_ID));
    EXPECT_EQ(ERROR_CODE.intValue(), errordata->getInt(KEY_ERROR_CODE));
    EXPECT_EQ(INTERNAL_CODE, errordata->getInt(KEY_INTERNAL_CODE));
    EXPECT_EQ(ERROR_MSG, errordata->getString(KEY_ERROR_MESSAGE));
    EXPECT_EQ(USER_MSG, errordata->getString(KEY_USER_MESSAGE));
    EXPECT_TRUE(isAboutNowSeconds(errordata->getLong(KEY_TIMESTAMP)));
}

TEST_F(ErrorHeaderTest, negativeInternalCodeMslObject)
{
    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, -17, ERROR_MSG, USER_MSG);
    EXPECT_EQ(-1, errorHeader->getInternalCode());

    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, errorHeader);
    shared_ptr<MslObject> entityAuthDataMo = mo->getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
    EXPECT_EQ(*MslTestUtils::toMslObject(encoder, ENTITY_AUTH_DATA), *entityAuthDataMo);
    shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_ERRORDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> errordata = encoder->parseObject(plaintext);
    shared_ptr<ByteArray> signature = mo->getBytes(KEY_SIGNATURE);
    EXPECT_TRUE(cryptoContext->verify(ciphertext, signature, encoder));

    EXPECT_TRUE(isAboutNowSeconds(errordata->getLong(KEY_TIMESTAMP)));
    EXPECT_EQ(MESSAGE_ID, errordata->getLong(KEY_MESSAGE_ID));
    EXPECT_EQ(ERROR_CODE.intValue(), errordata->getInt(KEY_ERROR_CODE));
    EXPECT_FALSE(errordata->has(KEY_INTERNAL_CODE));
    EXPECT_EQ(ERROR_MSG, errordata->getString(KEY_ERROR_MESSAGE));
    EXPECT_EQ(USER_MSG, errordata->getString(KEY_USER_MESSAGE));
}

TEST_F(ErrorHeaderTest, nullErrorMessageMslObject)
{
    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, "", USER_MSG);
    EXPECT_TRUE(errorHeader->getErrorMessage().empty());

    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, errorHeader);
    shared_ptr<MslObject> entityAuthDataMo = mo->getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
    EXPECT_EQ(*MslTestUtils::toMslObject(encoder, ENTITY_AUTH_DATA), *entityAuthDataMo);
    shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_ERRORDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> errordata = encoder->parseObject(plaintext);
    shared_ptr<ByteArray> signature = mo->getBytes(KEY_SIGNATURE);
    EXPECT_TRUE(cryptoContext->verify(ciphertext, signature, encoder));

    EXPECT_TRUE(isAboutNowSeconds(errordata->getLong(KEY_TIMESTAMP)));
    EXPECT_EQ(MESSAGE_ID, errordata->getLong(KEY_MESSAGE_ID));
    EXPECT_EQ(ERROR_CODE.intValue(), errordata->getInt(KEY_ERROR_CODE));
    EXPECT_EQ(INTERNAL_CODE, errordata->getInt(KEY_INTERNAL_CODE));
    EXPECT_FALSE(errordata->has(KEY_ERROR_MESSAGE));
    EXPECT_EQ(USER_MSG, errordata->getString(KEY_USER_MESSAGE));
}

TEST_F(ErrorHeaderTest, nullUserMessageMslObject)
{
    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, "");
    EXPECT_TRUE(errorHeader->getUserMessage().empty());

    shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, errorHeader);
    shared_ptr<MslObject> entityAuthDataMo = mo->getMslObject(KEY_ENTITY_AUTHENTICATION_DATA, encoder);
    EXPECT_EQ(*MslTestUtils::toMslObject(encoder, ENTITY_AUTH_DATA), *entityAuthDataMo);
    shared_ptr<ByteArray> ciphertext = mo->getBytes(KEY_ERRORDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> errordata = encoder->parseObject(plaintext);
    shared_ptr<ByteArray> signature = mo->getBytes(KEY_SIGNATURE);
    EXPECT_TRUE(cryptoContext->verify(ciphertext, signature, encoder));

    EXPECT_TRUE(isAboutNowSeconds(errordata->getLong(KEY_TIMESTAMP)));
    EXPECT_EQ(MESSAGE_ID, errordata->getLong(KEY_MESSAGE_ID));
    EXPECT_EQ(ERROR_CODE.intValue(), errordata->getInt(KEY_ERROR_CODE));
    EXPECT_EQ(INTERNAL_CODE, errordata->getInt(KEY_INTERNAL_CODE));
    EXPECT_EQ(ERROR_MSG, errordata->getString(KEY_ERROR_MESSAGE));
    EXPECT_FALSE(errordata->has(KEY_USER_MESSAGE));
}

TEST_F(ErrorHeaderTest, parseHeader)
{
    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);
    shared_ptr<Header> header = Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    EXPECT_TRUE(header);
    EXPECT_TRUE(instanceof<ErrorHeader>(header.get()));
    shared_ptr<ErrorHeader> moErrorHeader = dynamic_pointer_cast<ErrorHeader>(header);

    EXPECT_EQ(*errorHeader->getEntityAuthenticationData(), *moErrorHeader->getEntityAuthenticationData());
    EXPECT_EQ(*errorHeader->getTimestamp(), *moErrorHeader->getTimestamp());
    EXPECT_EQ(errorHeader->getErrorCode(), moErrorHeader->getErrorCode());
    EXPECT_EQ(errorHeader->getErrorMessage(), moErrorHeader->getErrorMessage());
    EXPECT_EQ(errorHeader->getInternalCode(), moErrorHeader->getInternalCode());
    EXPECT_EQ(errorHeader->getMessageId(), moErrorHeader->getMessageId());
    EXPECT_EQ(errorHeader->getUserMessage(), moErrorHeader->getUserMessage());
}

TEST_F(ErrorHeaderTest, missingEntityAuthDataCtor)
{
//    thrown.expect(MslMessageException.class);
//    thrown.expectMslError(MslError::MESSAGE_ENTITY_NOT_FOUND);
    try {
        ErrorHeader eh(ctx, shared_ptr<EntityAuthenticationData>(), MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslMessageException& e) {
        EXPECT_EQ(MslError::MESSAGE_ENTITY_NOT_FOUND, e.getError());
    }
}

TEST_F(ErrorHeaderTest, missingEntityAuthDataParseHeader)
{
//    thrown.expect(MslMessageException.class);
//    thrown.expectMslError(MslError::MESSAGE_ENTITY_NOT_FOUND);

    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    EXPECT_FALSE(errorHeaderMo->remove(KEY_ENTITY_AUTHENTICATION_DATA).isNull());

    try {
        Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslMessageException& e) {
        EXPECT_EQ(MslError::MESSAGE_ENTITY_NOT_FOUND, e.getError());
    }
}

TEST_F(ErrorHeaderTest, invalidEntityAuthData)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError::MSL_PARSE_ERROR);

    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    errorHeaderMo->put<string>(KEY_ENTITY_AUTHENTICATION_DATA, "x");

    try {
        Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(ErrorHeaderTest, missingSignature)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError::MSL_PARSE_ERROR);

    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    EXPECT_FALSE(errorHeaderMo->remove(KEY_SIGNATURE).isNull());

    try {
        Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(ErrorHeaderTest, invalidSignature)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError::MSL_PARSE_ERROR);

    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    errorHeaderMo->put<bool>(KEY_SIGNATURE, false);

    try {
        Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(ErrorHeaderTest, incorrectSignature)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError::MESSAGE_VERIFICATION_FAILED);

    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    errorHeaderMo->put(KEY_SIGNATURE, Base64::decode("AAA="));

    try {
        Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::MESSAGE_VERIFICATION_FAILED, e.getError());
    }
}

TEST_F(ErrorHeaderTest, missingErrordata)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError::MSL_PARSE_ERROR);

    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    EXPECT_FALSE(errorHeaderMo->remove(KEY_ERRORDATA).isNull());

    try {
        Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(ErrorHeaderTest, invalidErrordata)
{
//    thrown.expect(MslCryptoException.class);
//    thrown.expectMslError(MslError::CIPHERTEXT_ENVELOPE_PARSE_ERROR);

    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    // This tests invalid but trusted error data so we must sign it.
    shared_ptr<ByteArray> errordata = make_shared<ByteArray>(1);
    (*errordata)[0] = 'x';
    errorHeaderMo->put(KEY_ERRORDATA, errordata);
    shared_ptr<ByteArray> signature = cryptoContext->sign(errordata, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::CIPHERTEXT_ENVELOPE_PARSE_ERROR, e.getError());
    }
}

TEST_F(ErrorHeaderTest, emptyErrordata)
{
//    thrown.expect(MslMessageException.class);
//    thrown.expectMslError(MslError::HEADER_DATA_MISSING);

    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    // This tests empty but trusted error data so we must sign it.
    shared_ptr<ByteArray> ciphertext = make_shared<ByteArray>(0);
    errorHeaderMo->put(KEY_ERRORDATA, ciphertext);
    shared_ptr<ByteArray> signature = cryptoContext->sign(ciphertext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_SIGNATURE, signature);

    try {
        Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslMessageException& e) {
        EXPECT_EQ(MslError::HEADER_DATA_MISSING, e.getError());
    }
}

TEST_F(ErrorHeaderTest, missingTimestamp)
{
    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    // Before modifying the error data we need to decrypt it.
    shared_ptr<ByteArray> ciphertext = errorHeaderMo->getBytes(KEY_ERRORDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> errordata = encoder->parseObject(plaintext);

    // After modifying the error data we need to encrypt it.
    EXPECT_FALSE(errordata->remove(KEY_TIMESTAMP).isNull());
    shared_ptr<ByteArray> modifiedPlaintext = encoder->encodeObject(errordata, ENCODER_FORMAT);
    shared_ptr<ByteArray> modifiedCiphertext = cryptoContext->encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_ERRORDATA, modifiedCiphertext);

    // The error data must be signed otherwise the error data will not be
    // processed.
    shared_ptr<ByteArray> modifiedSignature = cryptoContext->sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_SIGNATURE, modifiedSignature);

    EXPECT_NO_THROW(Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS));
}

TEST_F(ErrorHeaderTest, invalidTimestamp)
{
    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    // Before modifying the error data we need to decrypt it.
    shared_ptr<ByteArray> ciphertext = errorHeaderMo->getBytes(KEY_ERRORDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> errordata = encoder->parseObject(plaintext);

    // After modifying the error data we need to encrypt it.
    errordata->put<string>(KEY_TIMESTAMP, "x");
    const string modifiedPlaintextStr = errordata->toString();
    shared_ptr<ByteArray> modifiedPlaintext = make_shared<ByteArray>(modifiedPlaintextStr.begin(), modifiedPlaintextStr.begin());
    shared_ptr<ByteArray> modifiedCiphertext = cryptoContext->encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_ERRORDATA, modifiedCiphertext);

    // The error data must be signed otherwise the error data will not be
    // processed.
    shared_ptr<ByteArray> modifiedSignature = cryptoContext->sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_SIGNATURE, modifiedSignature);

    try {
        Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(ErrorHeaderTest, missingMessageId)
{
    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    // Before modifying the error data we need to decrypt it.
    shared_ptr<ByteArray> ciphertext = errorHeaderMo->getBytes(KEY_ERRORDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> errordata = encoder->parseObject(plaintext);

    // After modifying the error data we need to encrypt it.
    EXPECT_FALSE(errordata->remove(KEY_MESSAGE_ID).isNull());
    const string modifiedPlaintextStr = errordata->toString();
    shared_ptr<ByteArray> modifiedPlaintext = make_shared<ByteArray>(modifiedPlaintextStr.begin(), modifiedPlaintextStr.end());
    shared_ptr<ByteArray> modifiedCiphertext = cryptoContext->encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_ERRORDATA, modifiedCiphertext);

    // The error data must be signed otherwise the error data will not be
    // processed.
    shared_ptr<ByteArray> modifiedSignature = cryptoContext->sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_SIGNATURE, modifiedSignature);

    try {
        Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(ErrorHeaderTest, invalidMessageId)
{
    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    // Before modifying the error data we need to decrypt it.
    shared_ptr<ByteArray> ciphertext = errorHeaderMo->getBytes(KEY_ERRORDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> errordata = encoder->parseObject(plaintext);

    // After modifying the error data we need to encrypt it.
    errordata->put<string>(KEY_MESSAGE_ID, "x");
    const string modifiedPlaintextStr = errordata->toString();
    shared_ptr<ByteArray> modifiedPlaintext = make_shared<ByteArray>(modifiedPlaintextStr.begin(), modifiedPlaintextStr.end());
    shared_ptr<ByteArray> modifiedCiphertext = cryptoContext->encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_ERRORDATA, modifiedCiphertext);

    // The error data must be signed otherwise the error data will not be
    // processed.
    shared_ptr<ByteArray> modifiedSignature = cryptoContext->sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_SIGNATURE, modifiedSignature);

    try {
        Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(ErrorHeaderTest, negativeMessageIdCtor)
{
//(expected = MslInternalException.class)
    EXPECT_THROW(ErrorHeader(ctx, ENTITY_AUTH_DATA, -1, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG), MslInternalException);
}

TEST_F(ErrorHeaderTest, tooLargeMessageIdCtor)
{
//(expected = MslInternalException.class)
    EXPECT_THROW(ErrorHeader(ctx, ENTITY_AUTH_DATA, MslConstants::MAX_LONG_VALUE + 1, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG), MslInternalException);
}

TEST_F(ErrorHeaderTest, negativeMessageIdParseHeader)
{
    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    // Before modifying the error data we need to decrypt it.
    shared_ptr<ByteArray> ciphertext = errorHeaderMo->getBytes(KEY_ERRORDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> errordata = encoder->parseObject(plaintext);

    // After modifying the error data we need to encrypt it.
    errordata->put<int64_t>(KEY_MESSAGE_ID, -1L);
    const string modifiedPlaintextStr = errordata->toString();
    shared_ptr<ByteArray> modifiedPlaintext = make_shared<ByteArray>(modifiedPlaintextStr.begin(), modifiedPlaintextStr.end());
    shared_ptr<ByteArray> modifiedCiphertext = cryptoContext->encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_ERRORDATA, modifiedCiphertext);

    // The error data must be signed otherwise the error data will not be
    // processed.
    shared_ptr<ByteArray> modifiedSignature = cryptoContext->sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_SIGNATURE, modifiedSignature);

    try {
        Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslMessageException& e) {
        EXPECT_EQ(MslError::MESSAGE_ID_OUT_OF_RANGE, e.getError());
    }
}

TEST_F(ErrorHeaderTest, tooLargeMessageIdParseHeader)
{
//    thrown.expect(MslMessageException.class);
//    thrown.expectMslError(MslError::MESSAGE_ID_OUT_OF_RANGE);

    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    // Before modifying the error data we need to decrypt it.
    shared_ptr<ByteArray> ciphertext = errorHeaderMo->getBytes(KEY_ERRORDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> errordata = encoder->parseObject(plaintext);

    // After modifying the error data we need to encrypt it.
    errordata->put<int64_t>(KEY_MESSAGE_ID, MslConstants::MAX_LONG_VALUE + 1);
    const string modifiedPlaintextStr = errordata->toString();
    shared_ptr<ByteArray> modifiedPlaintext = make_shared<ByteArray>(modifiedPlaintextStr.begin(), modifiedPlaintextStr.end());
    shared_ptr<ByteArray> modifiedCiphertext = cryptoContext->encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_ERRORDATA, modifiedCiphertext);

    // The error data must be signed otherwise the error data will not be
    // processed.
    shared_ptr<ByteArray> modifiedSignature = cryptoContext->sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_SIGNATURE, modifiedSignature);

    try {
        Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslMessageException& e) {
        EXPECT_EQ(MslError::MESSAGE_ID_OUT_OF_RANGE, e.getError());
    }
}

TEST_F(ErrorHeaderTest, missingErrorCode)
{
    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    // Before modifying the error data we need to decrypt it.
    shared_ptr<ByteArray> ciphertext = errorHeaderMo->getBytes(KEY_ERRORDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> errordata = encoder->parseObject(plaintext);

    // After modifying the error data we need to encrypt it.
    EXPECT_FALSE(errordata->remove(KEY_ERROR_CODE).isNull());
    const string modifiedPlaintextStr = errordata->toString();
    shared_ptr<ByteArray> modifiedPlaintext = make_shared<ByteArray>(modifiedPlaintextStr.begin(), modifiedPlaintextStr.end());
    shared_ptr<ByteArray> modifiedCiphertext = cryptoContext->encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_ERRORDATA, modifiedCiphertext);

    // The error data must be signed otherwise the error data will not be
    // processed.
    shared_ptr<ByteArray> modifiedSignature = cryptoContext->sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_SIGNATURE, modifiedSignature);

    try {
        Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(ErrorHeaderTest, invalidErrorCode)
{
    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    // Before modifying the error data we need to decrypt it.
    shared_ptr<ByteArray> ciphertext = errorHeaderMo->getBytes(KEY_ERRORDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> errordata = encoder->parseObject(plaintext);

    // After modifying the error data we need to encrypt it.
    errordata->put<string>(KEY_ERROR_CODE, "x");
    const string modifiedPlaintextStr = errordata->toString();
    shared_ptr<ByteArray> modifiedPlaintext = make_shared<ByteArray>(modifiedPlaintextStr.begin(), modifiedPlaintextStr.end());
    shared_ptr<ByteArray> modifiedCiphertext = cryptoContext->encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_ERRORDATA, modifiedCiphertext);

    // The error data must be signed otherwise the error data will not be
    // processed.
    shared_ptr<ByteArray> modifiedSignature = cryptoContext->sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_SIGNATURE, modifiedSignature);

    try {
        Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(ErrorHeaderTest, missingInternalCode)
{
    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    // Before modifying the error data we need to decrypt it.
    shared_ptr<ByteArray> ciphertext = errorHeaderMo->getBytes(KEY_ERRORDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> errordata = encoder->parseObject(plaintext);

    // After modifying the error data we need to encrypt it.
    EXPECT_FALSE(errordata->remove(KEY_INTERNAL_CODE).isNull());
    const string modifiedPlaintextStr = errordata->toString();
    shared_ptr<ByteArray> modifiedPlaintext = make_shared<ByteArray>(modifiedPlaintextStr.begin(), modifiedPlaintextStr.end());
    shared_ptr<ByteArray> modifiedCiphertext = cryptoContext->encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_ERRORDATA, modifiedCiphertext);

    // The error data must be signed otherwise the error data will not be
    // processed.
    shared_ptr<ByteArray> modifiedSignature = cryptoContext->sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_SIGNATURE, modifiedSignature);

    shared_ptr<Header> moHeader = Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    shared_ptr<ErrorHeader> moErrorHeader = dynamic_pointer_cast<ErrorHeader>(moHeader);
    EXPECT_EQ(-1, moErrorHeader->getInternalCode());
}

TEST_F(ErrorHeaderTest, invalidInternalCode)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError::MSL_PARSE_ERROR);
//    thrown.expectMessageId(MESSAGE_ID);

    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    // Before modifying the error data we need to decrypt it.
    shared_ptr<ByteArray> ciphertext = errorHeaderMo->getBytes(KEY_ERRORDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> errordata = encoder->parseObject(plaintext);

    // After modifying the error data we need to encrypt it.
    errordata->put<string>(KEY_INTERNAL_CODE, "x");
    const string modifiedPlaintextStr = errordata->toString();
    shared_ptr<ByteArray> modifiedPlaintext = make_shared<ByteArray>(modifiedPlaintextStr.begin(), modifiedPlaintextStr.end());
    shared_ptr<ByteArray> modifiedCiphertext = cryptoContext->encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_ERRORDATA, modifiedCiphertext);

    // The error data must be signed otherwise the error data will not be
    // processed.
    shared_ptr<ByteArray> modifiedSignature = cryptoContext->sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_SIGNATURE, modifiedSignature);

    try {
        Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(ErrorHeaderTest, negativeInternalCode)
{
//    thrown.expect(MslMessageException.class);
//    thrown.expectMslError(MslError::INTERNAL_CODE_NEGATIVE);
//    thrown.expectMessageId(MESSAGE_ID);

    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    // Before modifying the error data we need to decrypt it.
    shared_ptr<ByteArray> ciphertext = errorHeaderMo->getBytes(KEY_ERRORDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> errordata = encoder->parseObject(plaintext);

    // After modifying the error data we need to encrypt it.
    errordata->put(KEY_INTERNAL_CODE, -17);
    const string modifiedPlaintextStr = errordata->toString();
    shared_ptr<ByteArray> modifiedPlaintext = make_shared<ByteArray>(modifiedPlaintextStr.begin(), modifiedPlaintextStr.end());
    shared_ptr<ByteArray> modifiedCiphertext = cryptoContext->encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_ERRORDATA, modifiedCiphertext);

    // The error data must be signed otherwise the error data will not be
    // processed.
    shared_ptr<ByteArray> modifiedSignature = cryptoContext->sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_SIGNATURE, modifiedSignature);

    try {
        Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslMessageException& e) {
        EXPECT_EQ(MslError::INTERNAL_CODE_NEGATIVE, e.getError());
        EXPECT_EQ(MESSAGE_ID, e.getMessageId());
    }
}

TEST_F(ErrorHeaderTest, missingErrorMessage)
{
    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    // Before modifying the error data we need to decrypt it.
    shared_ptr<ByteArray> ciphertext = errorHeaderMo->getBytes(KEY_ERRORDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> errordata = encoder->parseObject(plaintext);

    // After modifying the error data we need to encrypt it.
    EXPECT_FALSE(errordata->remove(KEY_ERROR_MESSAGE).isNull());
    const string modifiedPlaintextStr = errordata->toString();
    shared_ptr<ByteArray> modifiedPlaintext = make_shared<ByteArray>(modifiedPlaintextStr.begin(), modifiedPlaintextStr.end());
    shared_ptr<ByteArray> modifiedCiphertext = cryptoContext->encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_ERRORDATA, modifiedCiphertext);

    // The error data must be signed otherwise the error data will not be
    // processed.
    shared_ptr<ByteArray> modifiedSignature = cryptoContext->sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_SIGNATURE, modifiedSignature);

    shared_ptr<Header> moHeader = Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    shared_ptr<ErrorHeader> moErrorHeader = dynamic_pointer_cast<ErrorHeader>(moHeader);
    EXPECT_TRUE(moErrorHeader->getErrorMessage().empty());
}

TEST_F(ErrorHeaderTest, missingUserMessage)
{
    shared_ptr<ErrorHeader> errorHeader = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<MslObject> errorHeaderMo = MslTestUtils::toMslObject(encoder, errorHeader);

    // Before modifying the error data we need to decrypt it.
    shared_ptr<ByteArray> ciphertext = errorHeaderMo->getBytes(KEY_ERRORDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder);
    shared_ptr<MslObject> errordata = encoder->parseObject(plaintext);

    // After modifying the error data we need to encrypt it.
    EXPECT_FALSE(errordata->remove(KEY_USER_MESSAGE).isNull());
    const string modifiedPlaintextStr = errordata->toString();
    shared_ptr<ByteArray> modifiedPlaintext = make_shared<ByteArray>(modifiedPlaintextStr.begin(), modifiedPlaintextStr.end());
    shared_ptr<ByteArray> modifiedCiphertext = cryptoContext->encrypt(modifiedPlaintext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_ERRORDATA, modifiedCiphertext);

    // The error data must be signed otherwise the error data will not be
    // processed.
    shared_ptr<ByteArray> modifiedSignature = cryptoContext->sign(modifiedCiphertext, encoder, ENCODER_FORMAT);
    errorHeaderMo->put(KEY_SIGNATURE, modifiedSignature);

    shared_ptr<Header> moHeader = Header::parseHeader(ctx, errorHeaderMo, CRYPTO_CONTEXTS);
    shared_ptr<ErrorHeader> moErrorHeader = dynamic_pointer_cast<ErrorHeader>(moHeader);
    EXPECT_TRUE(moErrorHeader->getUserMessage().empty());
}

TEST_F(ErrorHeaderTest, equalsTimestamp)
{
    shared_ptr<ErrorHeader> errorHeaderA = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    sleep(1);  // FIXME: better way to do this? Adds a whole second to test runtime, currently +30%.
    shared_ptr<ErrorHeader> errorHeaderB = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<ErrorHeader> errorHeaderA2 = dynamic_pointer_cast<ErrorHeader>(Header::parseHeader(ctx, MslTestUtils::toMslObject(encoder, errorHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(errorHeaderA->equals(errorHeaderA));

    EXPECT_FALSE(errorHeaderA->equals(errorHeaderB));
    EXPECT_FALSE(errorHeaderB->equals(errorHeaderA));

    EXPECT_TRUE(errorHeaderA->equals(errorHeaderA2));
    EXPECT_TRUE(errorHeaderA2->equals(errorHeaderA));
}

TEST_F(ErrorHeaderTest, equalsMessageId)
{
    const int64_t messageIdA = 1;
    const int64_t messageIdB = 2;
    shared_ptr<ErrorHeader> errorHeaderA = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, messageIdA, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<ErrorHeader> errorHeaderB = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, messageIdB, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<ErrorHeader> errorHeaderA2 = dynamic_pointer_cast<ErrorHeader>(Header::parseHeader(ctx, MslTestUtils::toMslObject(encoder, errorHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(errorHeaderA->equals(errorHeaderA));

    EXPECT_FALSE(errorHeaderA->equals(errorHeaderB));
    EXPECT_FALSE(errorHeaderB->equals(errorHeaderA));

    EXPECT_TRUE(errorHeaderA->equals(errorHeaderA2));
    EXPECT_TRUE(errorHeaderA2->equals(errorHeaderA));
}

TEST_F(ErrorHeaderTest, equalsErrorCode)
{
    const MslConstants::ResponseCode errorCodeA = MslConstants::ResponseCode::FAIL;
    const MslConstants::ResponseCode errorCodeB = MslConstants::ResponseCode::TRANSIENT_FAILURE;
    shared_ptr<ErrorHeader> errorHeaderA = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, errorCodeA, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<ErrorHeader> errorHeaderB = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, errorCodeB, INTERNAL_CODE, ERROR_MSG, USER_MSG);
    shared_ptr<ErrorHeader> errorHeaderA2 = dynamic_pointer_cast<ErrorHeader>(Header::parseHeader(ctx, MslTestUtils::toMslObject(encoder, errorHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(errorHeaderA->equals(errorHeaderA));

    EXPECT_FALSE(errorHeaderA->equals(errorHeaderB));
    EXPECT_FALSE(errorHeaderB->equals(errorHeaderA));

    EXPECT_TRUE(errorHeaderA->equals(errorHeaderA2));
    EXPECT_TRUE(errorHeaderA2->equals(errorHeaderA));
}

TEST_F(ErrorHeaderTest, equalsInternalCode)
{
    const int32_t internalCodeA = 1;
    const int32_t internalCodeB = 2;
    shared_ptr<ErrorHeader> errorHeaderA = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, internalCodeA, ERROR_MSG, USER_MSG);
    shared_ptr<ErrorHeader> errorHeaderB = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, internalCodeB, ERROR_MSG, USER_MSG);
    shared_ptr<ErrorHeader> errorHeaderA2 = dynamic_pointer_cast<ErrorHeader>(Header::parseHeader(ctx, MslTestUtils::toMslObject(encoder, errorHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(errorHeaderA->equals(errorHeaderA));

    EXPECT_FALSE(errorHeaderA->equals(errorHeaderB));
    EXPECT_FALSE(errorHeaderB->equals(errorHeaderA));

    EXPECT_TRUE(errorHeaderA->equals(errorHeaderA2));
    EXPECT_TRUE(errorHeaderA2->equals(errorHeaderA));
}

TEST_F(ErrorHeaderTest, equalsErrorMessage)
{
    const string errorMsgA = "A";
    const string errorMsgB = "B";
    shared_ptr<ErrorHeader> errorHeaderA = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, errorMsgA, USER_MSG);
    shared_ptr<ErrorHeader> errorHeaderB = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, errorMsgB, USER_MSG);
    shared_ptr<ErrorHeader> errorHeaderC = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, "", USER_MSG);
    shared_ptr<ErrorHeader> errorHeaderA2 = dynamic_pointer_cast<ErrorHeader>(Header::parseHeader(ctx, MslTestUtils::toMslObject(encoder, errorHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(errorHeaderA->equals(errorHeaderA));

    EXPECT_FALSE(errorHeaderA->equals(errorHeaderB));
    EXPECT_FALSE(errorHeaderB->equals(errorHeaderA));

    EXPECT_FALSE(errorHeaderA->equals(errorHeaderC));
    EXPECT_FALSE(errorHeaderC->equals(errorHeaderA));

    EXPECT_TRUE(errorHeaderA->equals(errorHeaderA2));
    EXPECT_TRUE(errorHeaderA2->equals(errorHeaderA));
}

TEST_F(ErrorHeaderTest, equalsUserMessage)
{
    const string userMsgA = "A";
    const string userMsgB = "B";
    shared_ptr<ErrorHeader> errorHeaderA = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, userMsgA);
    shared_ptr<ErrorHeader> errorHeaderB = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, userMsgB);
    shared_ptr<ErrorHeader> errorHeaderC = make_shared<ErrorHeader>(ctx, ENTITY_AUTH_DATA, MESSAGE_ID, ERROR_CODE, INTERNAL_CODE, ERROR_MSG, "");
    shared_ptr<ErrorHeader> errorHeaderA2 = dynamic_pointer_cast<ErrorHeader>(Header::parseHeader(ctx, MslTestUtils::toMslObject(encoder, errorHeaderA), CRYPTO_CONTEXTS));

    EXPECT_TRUE(errorHeaderA->equals(errorHeaderA));

    EXPECT_FALSE(errorHeaderA->equals(errorHeaderB));
    EXPECT_FALSE(errorHeaderB->equals(errorHeaderA));

    EXPECT_FALSE(errorHeaderA->equals(errorHeaderC));
    EXPECT_FALSE(errorHeaderC->equals(errorHeaderA));

    EXPECT_TRUE(errorHeaderA->equals(errorHeaderA2));
    EXPECT_TRUE(errorHeaderA2->equals(errorHeaderA));
}

}}} // namespace netflix::msl::msg
