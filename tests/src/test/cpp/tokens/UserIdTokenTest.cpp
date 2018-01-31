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

#include <crypto/ICryptoContext.h>
#include <Date.h>
#include <gtest/gtest.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <io/MslEncoderFormat.h>
#include <io/MslEncoderFactory.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslException.h>
#include <MslInternalException.h>
#include <tokens/MasterToken.h>
#include <tokens/UserIdToken.h>
#include <util/MslContext.h>
#include <stdint.h>
#include <string>

#include "../util/MockMslContext.h"
#include "../util/MslTestUtils.h"
#include "../tokens/MockMslUser.h"

using netflix::msl::crypto::ICryptoContext;

using namespace std;
using namespace testing;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
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
/** Key master token serial number. */
const string KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
/** Key user ID token serial number. */
const string KEY_SERIAL_NUMBER = "serialnumber";
/** Key token user identification data. */
const string KEY_USERDATA = "userdata";

// userdata
/** Key issuer data. */
const string KEY_ISSUER_DATA = "issuerdata";
/** Key identity. */
const string KEY_IDENTITY = "identity";

const int64_t SERIAL_NUMBER = 42;

// issuer data
const string ISSUER_DATA_STR = "{ \"issuerid\" : 17 }";
#define BA(a) make_shared<ByteArray>(a.begin(), a.end())

//ostream & operator<<(ostream &os, shared_ptr<ByteArray>& b)
//{
//    string s(b.begin(), b.end());
//    os << s;
//    return os;
//}

} // namespace anonymous

class UserIdTokenTest : public ::testing::Test
{
public:
    UserIdTokenTest()
    : ENCODER_FORMAT(MslEncoderFormat::JSON)
    , RENEWAL_WINDOW(make_shared<Date>(Date::now()->getTime() + 60000))
    , EXPIRATION(make_shared<Date>(Date::now()->getTime() + 120000))
    , ctx_(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false))
    , encoder_(ctx_->getMslEncoderFactory())
    , MASTER_TOKEN(MslTestUtils::getMasterToken(ctx_, 1ll, 1ll))
    , ISSUER_DATA(encoder_->parseObject(BA(ISSUER_DATA_STR)))
    , USER(make_shared<MockMslUser>(312204600))  // MockEmailPasswordAuthenticationFactory.USER
    {
    }
protected:
    const MslEncoderFormat ENCODER_FORMAT;
    shared_ptr<Date> RENEWAL_WINDOW;
    shared_ptr<Date> EXPIRATION;
    shared_ptr<MslContext> ctx_;
    shared_ptr<MslEncoderFactory> encoder_;
    shared_ptr<MasterToken> MASTER_TOKEN;
    shared_ptr<MslObject> ISSUER_DATA;
    shared_ptr<MslUser> USER;
};

TEST_F(UserIdTokenTest, ctors)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    EXPECT_TRUE(userIdToken->isDecrypted());
    EXPECT_TRUE(userIdToken->isVerified());
    EXPECT_FALSE(userIdToken->isRenewable());
    EXPECT_FALSE(userIdToken->isExpired());
    EXPECT_TRUE(userIdToken->isBoundTo(MASTER_TOKEN));
    EXPECT_EQ(ISSUER_DATA, userIdToken->getIssuerData());
    EXPECT_EQ(USER, userIdToken->getUser());
    EXPECT_EQ(EXPIRATION->getTime() / MILLISECONDS_PER_SECOND, userIdToken->getExpiration()->getTime() / MILLISECONDS_PER_SECOND);
    EXPECT_EQ(MASTER_TOKEN->getSerialNumber(), userIdToken->getMasterTokenSerialNumber());
    EXPECT_EQ(RENEWAL_WINDOW->getTime() / MILLISECONDS_PER_SECOND, userIdToken->getRenewalWindow()->getTime() / MILLISECONDS_PER_SECOND);
    EXPECT_EQ(SERIAL_NUMBER, userIdToken->getSerialNumber());
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    EXPECT_TRUE(encode);

    shared_ptr<MslObject> mo = encoder_->parseObject(encode);
    shared_ptr<UserIdToken> moUserIdToken = make_shared<UserIdToken>(ctx_, mo, MASTER_TOKEN);
    EXPECT_EQ(userIdToken->isDecrypted(), moUserIdToken->isDecrypted());
    EXPECT_EQ(userIdToken->isVerified(), moUserIdToken->isVerified());
    EXPECT_EQ(userIdToken->isRenewable(), moUserIdToken->isRenewable());
    EXPECT_EQ(userIdToken->isExpired(), moUserIdToken->isExpired());
    EXPECT_TRUE(moUserIdToken->isBoundTo(MASTER_TOKEN));
    EXPECT_EQ(*userIdToken->getIssuerData(), *moUserIdToken->getIssuerData());
    EXPECT_TRUE(userIdToken->getUser()->equals(moUserIdToken->getUser()));
    EXPECT_EQ(userIdToken->getExpiration()->getTime() / MILLISECONDS_PER_SECOND, moUserIdToken->getExpiration()->getTime() / MILLISECONDS_PER_SECOND);
    EXPECT_EQ(userIdToken->getMasterTokenSerialNumber(), moUserIdToken->getMasterTokenSerialNumber());
    EXPECT_EQ(userIdToken->getRenewalWindow()->getTime() / MILLISECONDS_PER_SECOND, moUserIdToken->getRenewalWindow()->getTime() / MILLISECONDS_PER_SECOND);
    EXPECT_EQ(userIdToken->getSerialNumber(), moUserIdToken->getSerialNumber());
    shared_ptr<ByteArray> moEncode = moUserIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_EQ(*encode, *moEncode);
}

TEST_F(UserIdTokenTest, negativeSerialNumberCtor)
{
    const int64_t serialNumber = -1;
    EXPECT_THROW(UserIdToken(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumber, ISSUER_DATA, USER),
            MslInternalException);
}

TEST_F(UserIdTokenTest, tooLargeSerialNumberCtor)
{
    //@Test(expected = MslInternalException.class)
    const int64_t serialNumber = MslConstants::MAX_LONG_VALUE + 1;
    EXPECT_THROW(UserIdToken(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumber, ISSUER_DATA, USER),
            MslInternalException);
}

TEST_F(UserIdTokenTest, masterTokenMismatch)
{
    shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx_, 1, 1);
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, masterToken, SERIAL_NUMBER, ISSUER_DATA, USER);

    shared_ptr<MasterToken> moMasterToken = MslTestUtils::getMasterToken(ctx_, 1, 2);
    try {
        UserIdToken(ctx_, MslTestUtils::toMslObject(encoder_, userIdToken), moMasterToken);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_MASTERTOKEN_MISMATCH, e.getError());
    }
}

TEST_F(UserIdTokenTest, masterTokenNull)
{
    shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx_, 1, 1);
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, masterToken, SERIAL_NUMBER, ISSUER_DATA, USER);
    EXPECT_THROW(UserIdToken(ctx_, MslTestUtils::toMslObject(encoder_, userIdToken), shared_ptr<MasterToken>()), MslException);
}

TEST_F(UserIdTokenTest, inconsistentExpiration)
{
    shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() - 1);
    shared_ptr<Date> renewalWindow = Date::now();
    EXPECT_TRUE(expiration->before(renewalWindow));
    EXPECT_THROW(UserIdToken(ctx_, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER), MslInternalException);
}

TEST_F(UserIdTokenTest, inconsistentExpirationJson)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    const int64_t now = Date::now()->getTime();
    const int64_t earlier = Date::now()->getTime() - 1000;
    tokendataMo->put(KEY_EXPIRATION, earlier);
    tokendataMo->put(KEY_RENEWAL_WINDOW, now);
    mo->put(KEY_TOKENDATA, encoder_->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_EXPIRES_BEFORE_RENEWAL, e.getError());
    }
}

TEST_F(UserIdTokenTest, missingTokendata)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    EXPECT_FALSE(mo->remove(KEY_TOKENDATA).isNull());

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserIdTokenTest, invalidTokendata)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    ++(*tokendata)[0];
    mo->put(KEY_TOKENDATA, tokendata);

    EXPECT_THROW(UserIdToken(ctx_, mo, MASTER_TOKEN), MslEncodingException);
}

TEST_F(UserIdTokenTest, missingSignature)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    EXPECT_FALSE(mo->remove(KEY_SIGNATURE).isNull());

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserIdTokenTest, missingRenewalWindow)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    EXPECT_FALSE(tokendataMo->remove(KEY_RENEWAL_WINDOW).isNull());
    mo->put(KEY_TOKENDATA, encoder_->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserIdTokenTest, invalidRenewalWindow)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    tokendataMo->put<string>(KEY_RENEWAL_WINDOW, "x");
    mo->put(KEY_TOKENDATA, encoder_->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserIdTokenTest, missingExpiration)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    EXPECT_FALSE(tokendataMo->remove(KEY_EXPIRATION).isNull());
    mo->put(KEY_TOKENDATA, encoder_->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserIdTokenTest, invalidExpiration)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    tokendataMo->put<string>(KEY_EXPIRATION, "x");
    mo->put(KEY_TOKENDATA, encoder_->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserIdTokenTest, missingSerialNumber)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    EXPECT_FALSE(tokendataMo->remove(KEY_SERIAL_NUMBER).isNull());
    mo->put(KEY_TOKENDATA, encoder_->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserIdTokenTest, invalidSerialNumber)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    tokendataMo->put<string>(KEY_SERIAL_NUMBER, "x");
    mo->put(KEY_TOKENDATA, encoder_->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserIdTokenTest, negativeSerialNumber)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    tokendataMo->put(KEY_SERIAL_NUMBER, -1);
    mo->put(KEY_TOKENDATA, encoder_->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, e.getError());
    }
}

TEST_F(UserIdTokenTest, tooLargeSerialNumber)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    tokendataMo->put<int64_t>(KEY_SERIAL_NUMBER, MslConstants::MAX_LONG_VALUE + 1);
    mo->put(KEY_TOKENDATA, encoder_->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, e.getError());
    }
}

TEST_F(UserIdTokenTest, missingMasterTokenSerialNumber)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    EXPECT_FALSE(tokendataMo->remove(KEY_MASTER_TOKEN_SERIAL_NUMBER).isNull());
    mo->put(KEY_TOKENDATA, encoder_->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserIdTokenTest, invalidMasterTokenSerialNumber)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    tokendataMo->put<string>(KEY_MASTER_TOKEN_SERIAL_NUMBER, "x");
    mo->put(KEY_TOKENDATA, encoder_->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserIdTokenTest, negativeMasterTokenSerialNumber)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    tokendataMo->put<int64_t>(KEY_MASTER_TOKEN_SERIAL_NUMBER, -1);
    mo->put(KEY_TOKENDATA, encoder_->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, e.getError());
    }
}

TEST_F(UserIdTokenTest, tooLargeMasterTokenSerialNumber)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    tokendataMo->put<int64_t>(KEY_MASTER_TOKEN_SERIAL_NUMBER, MslConstants::MAX_LONG_VALUE + 1);
    mo->put(KEY_TOKENDATA, encoder_->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, e.getError());
    }
}

TEST_F(UserIdTokenTest, missingUserdata)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    EXPECT_FALSE(tokendataMo->remove(KEY_USERDATA).isNull());
    mo->put(KEY_TOKENDATA, encoder_->encodeObject(tokendataMo, ENCODER_FORMAT));

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserIdTokenTest, invalidUserdata)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    tokendataMo->put<string>(KEY_USERDATA, "x");

    shared_ptr<ICryptoContext> cryptoContext = ctx_->getMslCryptoContext();
    shared_ptr<ByteArray> modifiedTokendata = encoder_->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder_, ENCODER_FORMAT);
    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_TOKENDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserIdTokenTest, emptyUserdata)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);

    shared_ptr<ICryptoContext> cryptoContext = ctx_->getMslCryptoContext();
    shared_ptr<ByteArray> ciphertext = make_shared<ByteArray>();
    tokendataMo->put(KEY_USERDATA, ciphertext);
    shared_ptr<ByteArray> modifiedTokendata = encoder_->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder_, ENCODER_FORMAT);
    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_USERDATA_MISSING, e.getError());
    }
}

TEST_F(UserIdTokenTest, corruptUserdata)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    // This is testing user data that is verified but corrupt.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    shared_ptr<ByteArray> userdata = tokendataMo->getBytes(KEY_USERDATA);
    ++(*userdata)[userdata->size()-1];
    tokendataMo->put(KEY_USERDATA, userdata);

    shared_ptr<ICryptoContext> cryptoContext = ctx_->getMslCryptoContext();
    shared_ptr<ByteArray> modifiedTokendata = encoder_->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder_, ENCODER_FORMAT);
    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    EXPECT_THROW(UserIdToken(ctx_, mo, MASTER_TOKEN), MslCryptoException);
}

TEST_F(UserIdTokenTest, emptyUser)
{
//    thrown.expect(MslException.class);
//    thrown.expectMslError(MslError.USERIDTOKEN_IDENTITY_INVALID);

    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ICryptoContext> cryptoContext = ctx_->getMslCryptoContext();

    // Before modifying the user data we need to decrypt it.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    shared_ptr<ByteArray> ciphertext = tokendataMo->getBytes(KEY_USERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder_);
    shared_ptr<MslObject> userdataMo = encoder_->parseObject(plaintext);

    // After modifying the user data we need to encrypt it.
    userdataMo->put<string>(KEY_IDENTITY, "");
    shared_ptr<ByteArray> userdata = cryptoContext->encrypt(encoder_->encodeObject(userdataMo, ENCODER_FORMAT), encoder_, ENCODER_FORMAT);
    tokendataMo->put(KEY_USERDATA, userdata);

    // The tokendata must be signed otherwise the user data will not be
    // processed.
    shared_ptr<ByteArray> modifiedTokendata = encoder_->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder_, ENCODER_FORMAT);
    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_IDENTITY_INVALID, e.getError());
    }
}

TEST_F(UserIdTokenTest, missingUser)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR);

    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ICryptoContext> cryptoContext = ctx_->getMslCryptoContext();

    // Before modifying the user data we need to decrypt it.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    shared_ptr<ByteArray> ciphertext = tokendataMo->getBytes(KEY_USERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder_);
    shared_ptr<MslObject> userdataMo = encoder_->parseObject(plaintext);

    // After modifying the user data we need to encrypt it.
    userdataMo->remove(KEY_IDENTITY);
    shared_ptr<ByteArray> userdata = cryptoContext->encrypt(encoder_->encodeObject(userdataMo, ENCODER_FORMAT), encoder_, ENCODER_FORMAT);
    tokendataMo->put(KEY_USERDATA, userdata);

    // The tokendata must be signed otherwise the user data will not be
    // processed.
    shared_ptr<ByteArray> modifiedTokendata = encoder_->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature = cryptoContext->sign(modifiedTokendata, encoder_, ENCODER_FORMAT);
    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_USERDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserIdTokenTest, invalidIssuerData)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR);

    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ICryptoContext> cryptoContext = ctx_->getMslCryptoContext();

    // Before modifying the user data we need to decrypt it.
    shared_ptr<ByteArray> tokendata = mo->getBytes(KEY_TOKENDATA);
    shared_ptr<MslObject> tokendataMo = encoder_->parseObject(tokendata);
    shared_ptr<ByteArray> ciphertext = tokendataMo->getBytes(KEY_USERDATA);
    shared_ptr<ByteArray> plaintext = cryptoContext->decrypt(ciphertext, encoder_);
    shared_ptr<MslObject> userdataMo = encoder_->parseObject(plaintext);

    // After modifying the user data we need to encrypt it.
    userdataMo->put<string>(KEY_ISSUER_DATA, "x");
    shared_ptr<ByteArray> userdata = cryptoContext->encrypt(encoder_->encodeObject(userdataMo, ENCODER_FORMAT), encoder_, ENCODER_FORMAT);
    tokendataMo->put(KEY_USERDATA, userdata);

    // The tokendata must be signed otherwise the user data will not be
    // processed.
    shared_ptr<ByteArray> modifiedTokendata = encoder_->encodeObject(tokendataMo, ENCODER_FORMAT);
    shared_ptr<ByteArray> signature =  cryptoContext->sign(modifiedTokendata, encoder_, ENCODER_FORMAT);
    mo->put(KEY_TOKENDATA, modifiedTokendata);
    mo->put(KEY_SIGNATURE, signature);

    try {
        UserIdToken(ctx_, mo, MASTER_TOKEN);
        ADD_FAILURE() << "Should have thrown";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::USERIDTOKEN_USERDATA_PARSE_ERROR, e.getError());
    }
}

TEST_F(UserIdTokenTest, notVerified)
{
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<ByteArray> encode = userIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    shared_ptr<MslObject> mo = encoder_->parseObject(encode);

    shared_ptr<ByteArray> signature = mo->getBytes(KEY_SIGNATURE);
    ++(*signature)[0];
    mo->put(KEY_SIGNATURE, signature);

    shared_ptr<UserIdToken> moUserIdToken = make_shared<UserIdToken>(ctx_, mo, MASTER_TOKEN);
    EXPECT_FALSE(moUserIdToken->isDecrypted());
    EXPECT_FALSE(moUserIdToken->isVerified());
    EXPECT_TRUE(moUserIdToken->isRenewable());
    EXPECT_FALSE(moUserIdToken->isExpired());
    EXPECT_EQ(userIdToken->isBoundTo(MASTER_TOKEN), moUserIdToken->isBoundTo(MASTER_TOKEN));
    EXPECT_FALSE(moUserIdToken->getUser());
    EXPECT_EQ(userIdToken->getExpiration()->getTime() / MILLISECONDS_PER_SECOND, moUserIdToken->getExpiration()->getTime() / MILLISECONDS_PER_SECOND);
    EXPECT_EQ(userIdToken->getMasterTokenSerialNumber(), moUserIdToken->getMasterTokenSerialNumber());
    EXPECT_EQ(userIdToken->getRenewalWindow()->getTime() / MILLISECONDS_PER_SECOND, moUserIdToken->getRenewalWindow()->getTime() / MILLISECONDS_PER_SECOND);
    EXPECT_EQ(userIdToken->getSerialNumber(), moUserIdToken->getSerialNumber());
    shared_ptr<ByteArray> moEncode = moUserIdToken->toMslEncoding(encoder_, ENCODER_FORMAT);
    EXPECT_TRUE(moEncode);
    EXPECT_NE(encode, moEncode);
}

TEST_F(UserIdTokenTest, isRenewable)
{
    shared_ptr<Date> renewalWindow = Date::now();
    shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 1000);
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);

    shared_ptr<Date> now = Date::now();
    EXPECT_TRUE(userIdToken->isRenewable());
    EXPECT_TRUE(userIdToken->isRenewable(now));
    EXPECT_FALSE(userIdToken->isExpired());
    EXPECT_FALSE(userIdToken->isExpired(now));

    shared_ptr<Date> before = make_shared<Date>(renewalWindow->getTime() - 1000);
    EXPECT_FALSE(userIdToken->isRenewable(before));
    EXPECT_FALSE(userIdToken->isExpired(before));

    shared_ptr<Date> after = make_shared<Date>(expiration->getTime() + 1000);
    EXPECT_TRUE(userIdToken->isRenewable(after));
    EXPECT_TRUE(userIdToken->isExpired(after));
}

TEST_F(UserIdTokenTest, isExpired)
{
    shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() - 1000);
    shared_ptr<Date> expiration = Date::now();
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);

    shared_ptr<Date> now = Date::now();
    EXPECT_TRUE(userIdToken->isRenewable());
    EXPECT_TRUE(userIdToken->isRenewable(now));
    EXPECT_TRUE(userIdToken->isExpired());
    EXPECT_TRUE(userIdToken->isExpired(now));

    shared_ptr<Date> before = make_shared<Date>(renewalWindow->getTime() - 1000);
    EXPECT_FALSE(userIdToken->isRenewable(before));
    EXPECT_FALSE(userIdToken->isExpired(before));

    shared_ptr<Date> after = make_shared<Date>(expiration->getTime() + 1000);
    EXPECT_TRUE(userIdToken->isRenewable(after));
    EXPECT_TRUE(userIdToken->isExpired(after));
}

TEST_F(UserIdTokenTest, notRenewableOrExpired)
{
    shared_ptr<Date> renewalWindow = make_shared<Date>(Date::now()->getTime() + 1000);
    shared_ptr<Date> expiration = make_shared<Date>(Date::now()->getTime() + 2000);
    shared_ptr<UserIdToken> userIdToken = make_shared<UserIdToken>(ctx_, renewalWindow, expiration, MASTER_TOKEN, SERIAL_NUMBER, ISSUER_DATA, USER);

    shared_ptr<Date> now = Date::now();
    EXPECT_FALSE(userIdToken->isRenewable());
    EXPECT_FALSE(userIdToken->isRenewable(now));
    EXPECT_FALSE(userIdToken->isExpired());
    EXPECT_FALSE(userIdToken->isExpired(now));

    shared_ptr<Date> before = make_shared<Date>(renewalWindow->getTime() - 1000);
    EXPECT_FALSE(userIdToken->isRenewable(before));
    EXPECT_FALSE(userIdToken->isExpired(before));

    shared_ptr<Date> after = make_shared<Date>(expiration->getTime() + 1000);
    EXPECT_TRUE(userIdToken->isRenewable(after));
    EXPECT_TRUE(userIdToken->isExpired(after));
}

TEST_F(UserIdTokenTest, isBoundTo)
{
    shared_ptr<MasterToken> masterTokenA = MslTestUtils::getMasterToken(ctx_, 1, 1);
    shared_ptr<UserIdToken> userIdTokenA = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, masterTokenA, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<MasterToken> masterTokenB = MslTestUtils::getMasterToken(ctx_, 1, 2);
    shared_ptr<UserIdToken> userIdTokenB = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, masterTokenB, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<MasterToken> emptyMasterToken;

    EXPECT_TRUE(userIdTokenA->isBoundTo(masterTokenA));
    EXPECT_FALSE(userIdTokenA->isBoundTo(masterTokenB));
    EXPECT_FALSE(userIdTokenA->isBoundTo(emptyMasterToken));
    EXPECT_TRUE(userIdTokenB->isBoundTo(masterTokenB));
    EXPECT_FALSE(userIdTokenB->isBoundTo(masterTokenA));
    EXPECT_FALSE(userIdTokenB->isBoundTo(emptyMasterToken));
}

TEST_F(UserIdTokenTest, equalsSerialNumber)
{
    const int64_t serialNumberA = 1;
    const int64_t serialNumberB = 2;
    shared_ptr<UserIdToken> userIdTokenA = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumberA, ISSUER_DATA, USER);
    shared_ptr<UserIdToken> userIdTokenB = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, MASTER_TOKEN, serialNumberB, ISSUER_DATA, USER);
    shared_ptr<UserIdToken> userIdTokenA2 = make_shared<UserIdToken>(ctx_, MslTestUtils::toMslObject(encoder_, userIdTokenA), MASTER_TOKEN);

    EXPECT_EQ(*userIdTokenA, *userIdTokenA);
    EXPECT_EQ(userIdTokenA->uniqueKey(), userIdTokenA->uniqueKey());

    EXPECT_NE(*userIdTokenA, *userIdTokenB);
    EXPECT_NE(*userIdTokenB, *userIdTokenA);
    EXPECT_NE(userIdTokenA->uniqueKey(), userIdTokenB->uniqueKey());

    EXPECT_EQ(*userIdTokenA, *userIdTokenA2);
    EXPECT_EQ(*userIdTokenA2, *userIdTokenA);
    EXPECT_EQ(userIdTokenA->uniqueKey(), userIdTokenA2->uniqueKey());
}

TEST_F(UserIdTokenTest, equalsMasterTokenSerialNumber)
{
    shared_ptr<MasterToken> masterTokenA = MslTestUtils::getMasterToken(ctx_, 1, 1);
    shared_ptr<MasterToken> masterTokenB = MslTestUtils::getMasterToken(ctx_, 1, 2);
    shared_ptr<UserIdToken> userIdTokenA = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, masterTokenA, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<UserIdToken> userIdTokenB = make_shared<UserIdToken>(ctx_, RENEWAL_WINDOW, EXPIRATION, masterTokenB, SERIAL_NUMBER, ISSUER_DATA, USER);
    shared_ptr<UserIdToken> userIdTokenA2 = make_shared<UserIdToken>(ctx_, MslTestUtils::toMslObject(encoder_, userIdTokenA), masterTokenA);

    EXPECT_EQ(*userIdTokenA, *userIdTokenA);
    EXPECT_EQ(userIdTokenA->uniqueKey(), userIdTokenA->uniqueKey());

    EXPECT_NE(*userIdTokenA, *userIdTokenB);
    EXPECT_NE(*userIdTokenB, *userIdTokenA);
    EXPECT_NE(userIdTokenA->uniqueKey(), userIdTokenB->uniqueKey());

    EXPECT_EQ(*userIdTokenA, *userIdTokenA2);
    EXPECT_EQ(*userIdTokenA2, *userIdTokenA);
    EXPECT_EQ(userIdTokenA->uniqueKey(), userIdTokenA2->uniqueKey());
}

}}} // namespace netflix::msl::tokens
