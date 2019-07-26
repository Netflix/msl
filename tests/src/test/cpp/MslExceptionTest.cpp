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
#include <entityauth/EntityAuthenticationData.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <io/DefaultMslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <MslException.h>
#include <MslError.h>
#include <tokens/MasterToken.h>
#include <tokens/UserIdToken.h>
#include <userauth/UserAuthenticationData.h>
#include <userauth/UserAuthenticationScheme.h>

#include "tokens/MockMslUser.h"
#include "util/MockMslContext.h"
#include "util/MslTestUtils.h"

using namespace std;
using namespace testing;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::userauth;
using namespace netflix::msl::io;
using namespace netflix::msl::tokens;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {

namespace {

class MockEntityAuthenticationData : public EntityAuthenticationData
{
public:
    MockEntityAuthenticationData(const string& identity)
    : EntityAuthenticationData(EntityAuthenticationScheme::PSK)
    , identity(identity)
    {
        ON_CALL(*this, getIdentity())
                .WillByDefault(Return(identity));
    }
    MOCK_CONST_METHOD0(getIdentity, string());
    MOCK_CONST_METHOD2(getAuthData, shared_ptr<MslObject>(shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& format));
    MOCK_CONST_METHOD2(toMslEncoding, shared_ptr<ByteArray>(shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& format));
private:
    const string identity;
};

class MockUserAuthenticationData : public UserAuthenticationData
{
public:
    MockUserAuthenticationData(shared_ptr<ByteArray> encoding)
    : UserAuthenticationData(userauth::UserAuthenticationScheme::EMAIL_PASSWORD)
    , encoding(encoding)
    {
        ON_CALL(*this, toMslEncoding(_, _))
                .WillByDefault(Return(encoding));
    }
    MOCK_CONST_METHOD2(getAuthData, shared_ptr<MslObject>(shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& format));
    MOCK_CONST_METHOD2(toMslEncoding, shared_ptr<ByteArray>(shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& format));
protected:
    shared_ptr<ByteArray> encoding;
};

}

class MslExceptionTest : public ::testing::Test
{
};

TEST_F(MslExceptionTest, Constructors)
{
    // MslException from MslError
    MslException mslex1(MslError::DIGEST_ERROR);
    EXPECT_EQ(0ll, mslex1.getMessageId());
    EXPECT_EQ(MslError::DIGEST_ERROR, mslex1.getError());
    EXPECT_EQ(string("Error in digest."), string(mslex1.what()));
    EXPECT_EQ(shared_ptr<IException>(), mslex1.getCause());

    // MslException from MslError and detail string
    MslException mslex2(MslError::DIGEST_ERROR, "foobar");
    EXPECT_EQ(0ll, mslex2.getMessageId());
    EXPECT_EQ(MslError::DIGEST_ERROR, mslex2.getError());
    EXPECT_EQ(string("Error in digest. [foobar]"), string(mslex2.what()));
    EXPECT_EQ(shared_ptr<IException>(), mslex1.getCause());

    // MslException from MslError, detail string, and MslException cause
    MslException mslex3(MslError::DECRYPT_ERROR, "barfoo", mslex2);
    EXPECT_EQ(0ll, mslex3.getMessageId());
    EXPECT_EQ(MslError::DECRYPT_ERROR, mslex3.getError());
    EXPECT_EQ(string("Error decrypting ciphertext. [barfoo]"), string(mslex3.what()));
    shared_ptr<IException> exCause = mslex3.getCause();
    EXPECT_NE(shared_ptr<IException>(), exCause);
    EXPECT_TRUE(instanceof<MslException>(exCause.get()));
    shared_ptr<MslException> mslexCause = dynamic_pointer_cast<MslException>(exCause);
    EXPECT_EQ(MslError::DIGEST_ERROR, mslexCause->getError());
    EXPECT_EQ(string("Error in digest. [foobar]"), string(mslexCause->what()));

    // MslException from MslError and MslException cause
    MslException mslex6(MslError::DECRYPT_ERROR, mslex2);
    EXPECT_EQ(0ll, mslex6.getMessageId());
    EXPECT_EQ(MslError::DECRYPT_ERROR, mslex6.getError());
    EXPECT_EQ(string("Error decrypting ciphertext."), string(mslex6.what()));
    exCause = mslex6.getCause();
    EXPECT_NE(shared_ptr<IException>(), exCause);
    EXPECT_TRUE(instanceof<MslException>(exCause.get()));
    mslexCause = dynamic_pointer_cast<MslException>(exCause);
    EXPECT_EQ(MslError::DIGEST_ERROR, mslexCause->getError());
    EXPECT_EQ(string("Error in digest. [foobar]"), string(mslexCause->what()));
}

TEST_F(MslExceptionTest, MessageId)
{
    MslException mslex(MslError::CIPHERTEXT_BAD_PADDING);
    mslex.setMessageId(100);
    EXPECT_EQ(100ll, mslex.getMessageId());
    mslex.setMessageId(200).setMessageId(300);
    EXPECT_EQ(100ll, mslex.getMessageId());  // cannot change once set
    EXPECT_EQ(400ll, MslException(MslError::CIPHERTEXT_BAD_PADDING).setMessageId(400).getMessageId());
    EXPECT_THROW(MslException(MslError::CIPHERTEXT_BAD_PADDING).setMessageId(MslConstants::MAX_LONG_VALUE+1), std::out_of_range);
}

TEST_F(MslExceptionTest, CauseRecursion)
{
    MslException mslex1(MslError::CIPHERTEXT_BAD_PADDING);
    MslException mslex2(MslError::CIPHERTEXT_ENVELOPE_ENCODE_ERROR, mslex1);
    mslex2.setMessageId(222ull);
    MslException mslex3(MslError::CIPHERTEXT_ENVELOPE_PARSE_ERROR, mslex2);
    MslException mslex4(MslError::CIPHERTEXT_ILLEGAL_BLOCK_SIZE, mslex3);
    EXPECT_EQ(4u, mslex4.getDepth());
    EXPECT_EQ(222l, mslex4.getMessageId());
    mslex4.setMessageId(444ull);
    EXPECT_EQ(222ll, mslex4.getMessageId()); // can't change if set somewhere in chain
    mslex1.setMessageId(111ull);
    EXPECT_EQ(111ll, mslex1.getMessageId());
    EXPECT_EQ(222ll, mslex4.getMessageId()); // should not change, chain makes copies
}

TEST_F(MslExceptionTest, Clone)
{
    MslException mslex1(MslError::DIGEST_ERROR);
    shared_ptr<IException> mslex1Clone = mslex1.clone();
    EXPECT_TRUE(instanceof<MslException>(mslex1Clone.get()));
}

TEST_F(MslExceptionTest, MasterToken)
{
    MslException me(MslError::DIGEST_ERROR);
    shared_ptr<MasterToken> mt1;
    me.setMasterToken(mt1);
    EXPECT_FALSE(me.getMasterToken());

    // make a mastertoken
    shared_ptr<MslContext> ctx = make_shared<MockMslContext >(EntityAuthenticationScheme::PSK, false);
    const int64_t sequenceNumber = 1111;
    mt1 = MslTestUtils::getMasterToken(ctx, sequenceNumber, 2222);

    // set / get
    me.setMasterToken(mt1);
    EXPECT_EQ(mt1.get(), me.getMasterToken().get());
    EXPECT_EQ(sequenceNumber, me.getMasterToken()->getSequenceNumber());

    // can't set again once set
    shared_ptr<MasterToken> mt2 = MslTestUtils::getMasterToken(ctx, sequenceNumber + 1, 2222);
    me.setMasterToken(mt2);
    EXPECT_NE(mt2.get(), me.getMasterToken().get());
    EXPECT_EQ(mt1.get(), me.getMasterToken().get());
    EXPECT_EQ(sequenceNumber, me.getMasterToken()->getSequenceNumber());
}

TEST_F(MslExceptionTest, EntityAuthenticationData)
{
    MslException me(MslError::DIGEST_ERROR);
    shared_ptr<EntityAuthenticationData> ead1;
    me.setEntityAuthenticationData(ead1);
    EXPECT_FALSE(me.getEntityAuthenticationData());

    // set / get
    ead1 = make_shared<NiceMock<MockEntityAuthenticationData>>("mead1");
    me.setEntityAuthenticationData(ead1);
    EXPECT_EQ("mead1", me.getEntityAuthenticationData()->getIdentity());

    // can't set again once set
    shared_ptr<EntityAuthenticationData> ead2 = make_shared<NiceMock<MockEntityAuthenticationData>>("mead2");
    me.setEntityAuthenticationData(ead2);
    EXPECT_EQ("mead1", me.getEntityAuthenticationData()->getIdentity());
}

TEST_F(MslExceptionTest, UserIdToken)
{
    MslException me(MslError::DIGEST_ERROR);
    shared_ptr<UserIdToken> uit1;
    me.setUserIdToken(uit1);
    EXPECT_FALSE(me.getUserIdToken());
    
    // make a useridtoken
    shared_ptr<MslContext> ctx = make_shared<MockMslContext >(EntityAuthenticationScheme::PSK, false);
    shared_ptr<MasterToken> mt = MslTestUtils::getMasterToken(ctx, 1111, 2222);
    const int64_t serialNumber = 3333;
    shared_ptr<MslUser> user = make_shared<NiceMock<MockMslUser>>("17");
    uit1 = MslTestUtils::getUserIdToken(ctx, mt, serialNumber, user);

    // set / get
    me.setUserIdToken(uit1);
    EXPECT_EQ(uit1.get(), me.getUserIdToken().get());
    EXPECT_EQ(serialNumber, me.getUserIdToken()->getSerialNumber());

    // can't set again once set
    shared_ptr<UserIdToken> uit2 = MslTestUtils::getUserIdToken(ctx, mt, serialNumber + 1, user);
    me.setUserIdToken(uit2);
    EXPECT_NE(uit2.get(), me.getUserIdToken().get());
    EXPECT_EQ(uit1.get(), me.getUserIdToken().get());
    EXPECT_EQ(serialNumber, me.getUserIdToken()->getSerialNumber());
}

TEST_F(MslExceptionTest, UserAuthenticationData)
{
    MslException me(MslError::DIGEST_ERROR);
    shared_ptr<UserAuthenticationData> uad1;
    me.setUserAuthenticationData(uad1);
    EXPECT_FALSE(me.getUserAuthenticationData());

    const char data1[] = { 0x1, 0x2, 0x3 };
    shared_ptr<ByteArray> encoding1 = make_shared<ByteArray>(data1, data1 + sizeof(data1));
    const char data2[] = { 0x4, 0x5, 0x6 };
    shared_ptr<ByteArray> encoding2 = make_shared<ByteArray>(data2, data2 + sizeof(data2));
    shared_ptr<MslEncoderFactory> mef = make_shared<DefaultMslEncoderFactory>();
    MslEncoderFormat format = MslEncoderFormat::JSON;

    // set / get
    uad1 = make_shared<NiceMock<MockUserAuthenticationData>>(encoding1);
    me.setUserAuthenticationData(uad1);
    EXPECT_EQ(*encoding1, *me.getUserAuthenticationData()->toMslEncoding(mef, format));

    // can't set again once set
    shared_ptr<UserAuthenticationData> uad2(make_shared<NiceMock<MockUserAuthenticationData>>(encoding1));
    me.setUserAuthenticationData(uad2);
    EXPECT_EQ(*encoding1, *me.getUserAuthenticationData()->toMslEncoding(mef, format));
}

}} // namespace netflix::msl
