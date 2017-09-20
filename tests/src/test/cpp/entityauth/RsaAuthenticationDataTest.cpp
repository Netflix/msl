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
#include <Macros.h>
#include <entityauth/RsaAuthenticationData.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslEntityAuthException.h>
#include <MslError.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslEncoderUtils.h>
#include <io/MslObject.h>
#include <util/MslContext.h>
#include <memory>

#include <entityauth/MockRsaAuthenticationFactory.h>
#include <util/MockMslContext.h>
#include <util/MslTestUtils.h>

using namespace std;
using namespace testing;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace entityauth {

namespace {
/** Key entity authentication scheme. */
const string KEY_SCHEME = "scheme";
/** Key entity authentication data-> */
const string KEY_AUTHDATA = "authdata";
/** Key entity identity. */
const string KEY_IDENTITY = "identity";
/** Key public key ID. */
const string KEY_PUBKEY_ID = "pubkeyid";
} // namespace anonymous

/**
 * RSA entity authentication data unit tests.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class RsaAuthenticationDataTest : public ::testing::Test
{
public:
	RsaAuthenticationDataTest()
	: ctx(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false))
	, encoder(ctx->getMslEncoderFactory())
	, format(MslEncoderFormat::JSON)
	{}

protected:
    /** MSL context. */
	shared_ptr<MockMslContext> ctx;
    /** MSL encoder factory. */
	shared_ptr<MslEncoderFactory> encoder;
	/** MSL encoder format. */
	const MslEncoderFormat format;
};

TEST_F(RsaAuthenticationDataTest, ctors)
{
	shared_ptr<RsaAuthenticationData> data = make_shared<RsaAuthenticationData>(MockRsaAuthenticationFactory::RSA_ESN, MockRsaAuthenticationFactory::RSA_PUBKEY_ID);
	EXPECT_EQ(MockRsaAuthenticationFactory::RSA_ESN, data->getIdentity());
	EXPECT_EQ(MockRsaAuthenticationFactory::RSA_PUBKEY_ID, data->getPublicKeyId());
	EXPECT_EQ(EntityAuthenticationScheme::RSA, data->getScheme());
	shared_ptr<MslObject> authdata = data->getAuthData(encoder, format);
	EXPECT_TRUE(authdata);
	shared_ptr<ByteArray> encode = data->toMslEncoding(encoder, format);
	EXPECT_TRUE(encode);

	shared_ptr<RsaAuthenticationData> moData = make_shared<RsaAuthenticationData>(authdata);
	EXPECT_EQ(data->getIdentity(), moData->getIdentity());
	EXPECT_EQ(data->getPublicKeyId(), moData->getPublicKeyId());
	EXPECT_EQ(data->getScheme(), moData->getScheme());
	shared_ptr<MslObject> moAuthdata = moData->getAuthData(encoder, format);
	EXPECT_TRUE(moAuthdata);
	EXPECT_TRUE(MslEncoderUtils::equalObjects(authdata, moAuthdata));
	shared_ptr<ByteArray> moEncode = moData->toMslEncoding(encoder, format);
	EXPECT_TRUE(moEncode);
	EXPECT_EQ(*encode, *moEncode);
}

TEST_F(RsaAuthenticationDataTest, encode)
{
	shared_ptr<RsaAuthenticationData> data = make_shared<RsaAuthenticationData>(MockRsaAuthenticationFactory::RSA_ESN, MockRsaAuthenticationFactory::RSA_PUBKEY_ID);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, data);
	EXPECT_EQ(EntityAuthenticationScheme::RSA.name(), mo->getString(KEY_SCHEME));
	shared_ptr<MslObject> authdata = mo->getMslObject(KEY_AUTHDATA, encoder);
	EXPECT_EQ(MockRsaAuthenticationFactory::RSA_ESN, authdata->getString(KEY_IDENTITY));
	EXPECT_EQ(MockRsaAuthenticationFactory::RSA_PUBKEY_ID, authdata->getString(KEY_PUBKEY_ID));
}

TEST_F(RsaAuthenticationDataTest, create)
{
	shared_ptr<RsaAuthenticationData> data = make_shared<RsaAuthenticationData>(MockRsaAuthenticationFactory::RSA_ESN, MockRsaAuthenticationFactory::RSA_PUBKEY_ID);
	shared_ptr<ByteArray> encode = data->toMslEncoding(encoder, format);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, data);
	shared_ptr<EntityAuthenticationData> entitydata = EntityAuthenticationData::create(ctx, mo);
	EXPECT_TRUE(entitydata);
	EXPECT_TRUE(instanceof<RsaAuthenticationData>(entitydata.get()));

	shared_ptr<RsaAuthenticationData> moData = dynamic_pointer_cast<RsaAuthenticationData>(entitydata);
	EXPECT_EQ(data->getIdentity(), moData->getIdentity());
	EXPECT_EQ(data->getPublicKeyId(), moData->getPublicKeyId());
	EXPECT_EQ(data->getScheme(), moData->getScheme());
	shared_ptr<MslObject> moAuthdata = moData->getAuthData(encoder, format);
	EXPECT_TRUE(moAuthdata);
	EXPECT_TRUE(MslEncoderUtils::equalObjects(data->getAuthData(encoder, format), moAuthdata));
	shared_ptr<ByteArray> moEncode = moData->toMslEncoding(encoder, format);
	EXPECT_TRUE(moEncode);
	EXPECT_EQ(*encode, *moEncode);
}

TEST_F(RsaAuthenticationDataTest, missingIdentity)
{
	shared_ptr<RsaAuthenticationData> data = make_shared<RsaAuthenticationData>(MockRsaAuthenticationFactory::RSA_ESN, MockRsaAuthenticationFactory::RSA_PUBKEY_ID);
	shared_ptr<MslObject> authdata = data->getAuthData(encoder, format);
	EXPECT_FALSE(authdata->remove(KEY_IDENTITY).isNull());
	try {
		RsaAuthenticationData rad(authdata);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslEncodingException& e) {
		EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
	}
}

TEST_F(RsaAuthenticationDataTest, missingPubkeyId)
{
	shared_ptr<RsaAuthenticationData> data = make_shared<RsaAuthenticationData>(MockRsaAuthenticationFactory::RSA_ESN, MockRsaAuthenticationFactory::RSA_PUBKEY_ID);
	shared_ptr<MslObject> authdata = data->getAuthData(encoder, format);
	EXPECT_FALSE(authdata->remove(KEY_PUBKEY_ID).isNull());
	try {
		RsaAuthenticationData rad(authdata);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslEncodingException& e) {
		EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
	}
}

TEST_F(RsaAuthenticationDataTest, equalsIdentity)
{
	const string identityA = MockRsaAuthenticationFactory::RSA_ESN + "A";
	const string identityB = MockRsaAuthenticationFactory::RSA_ESN + "B";
	shared_ptr<RsaAuthenticationData> dataA = make_shared<RsaAuthenticationData>(identityA, MockRsaAuthenticationFactory::RSA_PUBKEY_ID);
	shared_ptr<RsaAuthenticationData> dataB = make_shared<RsaAuthenticationData>(identityB, MockRsaAuthenticationFactory::RSA_PUBKEY_ID);
	shared_ptr<EntityAuthenticationData> dataA2 = EntityAuthenticationData::create(ctx, MslTestUtils::toMslObject(encoder, dataA));

	EXPECT_EQ(*dataA, *dataA);

	EXPECT_NE(*dataA, *dataB);
	EXPECT_NE(*dataB, *dataA);

	EXPECT_EQ(*dataA, *dataA2);
	EXPECT_EQ(*dataA2, *dataA);
}

TEST_F(RsaAuthenticationDataTest, equalsPubKeyId)
{
	const string pubkeyidA = MockRsaAuthenticationFactory::RSA_PUBKEY_ID + "A";
	const string pubkeyidB = MockRsaAuthenticationFactory::RSA_PUBKEY_ID + "B";
	shared_ptr<RsaAuthenticationData> dataA = make_shared<RsaAuthenticationData>(MockRsaAuthenticationFactory::RSA_ESN, pubkeyidA);
	shared_ptr<RsaAuthenticationData> dataB = make_shared<RsaAuthenticationData>(MockRsaAuthenticationFactory::RSA_ESN, pubkeyidB);
	shared_ptr<EntityAuthenticationData> dataA2 = EntityAuthenticationData::create(ctx, MslTestUtils::toMslObject(encoder, dataA));

	EXPECT_EQ(*dataA, *dataA);

	EXPECT_NE(*dataA, *dataB);
	EXPECT_NE(*dataB, *dataA);

	EXPECT_EQ(*dataA, *dataA2);
	EXPECT_EQ(*dataA2, *dataA);
}

}}} // namespace netflix::msl::entityauth
