/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
#include <entityauth/UnauthenticatedAuthenticationData.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslEntityAuthException.h>
#include <MslError.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslEncoderUtils.h>
#include <io/MslObject.h>
#include <util/MslContext.h>
#include <memory>

#include "../util/MockMslContext.h"
#include "../util/MslTestUtils.h"

using namespace std;
using namespace testing;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {

typedef vector<uint8_t> ByteArray;

namespace util {

namespace {
/** Key entity authentication scheme. */
const string KEY_SCHEME = "scheme";
/** Key entity authentication data. */
const string KEY_AUTHDATA = "authdata";
/** Key entity identity. */
const string KEY_IDENTITY = "identity";

const string IDENTITY = "identity";
}

/**
 * Unauthenticated entity authentication data unit tests.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class UnauthenticatedAuthenticationDataTest : public ::testing::Test
{
public:
	UnauthenticatedAuthenticationDataTest()
	: ctx(make_shared<MockMslContext>(EntityAuthenticationScheme::NONE, false))
	, encoder(ctx->getMslEncoderFactory())
	, format(MslEncoderFormat::JSON)
	{}

protected:
    /** MSL context. */
    shared_ptr<MslContext> ctx;
    /** MSL encoder factory. */
    shared_ptr<MslEncoderFactory> encoder;
    /** MSL encoder format. */
    const MslEncoderFormat format;
};

TEST_F(UnauthenticatedAuthenticationDataTest, ctors)
{
	shared_ptr<UnauthenticatedAuthenticationData> data = make_shared<UnauthenticatedAuthenticationData>(IDENTITY);
	EXPECT_EQ(IDENTITY, data->getIdentity());
	EXPECT_EQ(EntityAuthenticationScheme::NONE, data->getScheme());
	shared_ptr<MslObject> authdata = data->getAuthData(encoder, format);
	EXPECT_TRUE(authdata);
	shared_ptr<ByteArray> encode = data->toMslEncoding(encoder, format);
	EXPECT_TRUE(encode);

	shared_ptr<UnauthenticatedAuthenticationData> moData = make_shared<UnauthenticatedAuthenticationData>(authdata);
	EXPECT_EQ(data->getIdentity(), moData->getIdentity());
	EXPECT_EQ(data->getScheme(), moData->getScheme());
	shared_ptr<MslObject> moAuthdata = moData->getAuthData(encoder, format);
	EXPECT_TRUE(moAuthdata);
	EXPECT_TRUE(MslEncoderUtils::equalObjects(authdata, moAuthdata));
	shared_ptr<ByteArray> moEncode = moData->toMslEncoding(encoder, format);
	EXPECT_TRUE(moEncode);
	EXPECT_EQ(*encode, *moEncode);
}

TEST_F(UnauthenticatedAuthenticationDataTest, encode)
{
	shared_ptr<UnauthenticatedAuthenticationData> data = make_shared<UnauthenticatedAuthenticationData>(IDENTITY);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, data);
	EXPECT_EQ(EntityAuthenticationScheme::NONE.toString(), mo->getString(KEY_SCHEME));
	shared_ptr<MslObject> authdata = mo->getMslObject(KEY_AUTHDATA, encoder);
	EXPECT_EQ(IDENTITY, authdata->getString(KEY_IDENTITY));
}

TEST_F(UnauthenticatedAuthenticationDataTest, create)
{
	shared_ptr<UnauthenticatedAuthenticationData> data = make_shared<UnauthenticatedAuthenticationData>(IDENTITY);
	shared_ptr<ByteArray> encode = data->toMslEncoding(encoder, format);
	shared_ptr<MslObject> mo = MslTestUtils::toMslObject(encoder, data);
	shared_ptr<EntityAuthenticationData> entitydata = EntityAuthenticationData::create(ctx, mo);
	EXPECT_TRUE(entitydata);
	EXPECT_TRUE(instanceof<UnauthenticatedAuthenticationData>(entitydata.get()));

	shared_ptr<UnauthenticatedAuthenticationData> moData = dynamic_pointer_cast<UnauthenticatedAuthenticationData>(entitydata);
	EXPECT_EQ(data->getIdentity(), moData->getIdentity());
	EXPECT_EQ(data->getScheme(), moData->getScheme());
	shared_ptr<MslObject> moAuthdata = moData->getAuthData(encoder, format);
	EXPECT_TRUE(moAuthdata);
	EXPECT_TRUE(MslEncoderUtils::equalObjects(data->getAuthData(encoder, format), moAuthdata));
	shared_ptr<ByteArray> moEncode = moData->toMslEncoding(encoder, format);
	EXPECT_TRUE(moEncode);
	EXPECT_EQ(*encode, *moEncode);
}

TEST_F(UnauthenticatedAuthenticationDataTest, missingIdentity)
{
	shared_ptr<UnauthenticatedAuthenticationData> data = make_shared<UnauthenticatedAuthenticationData>(IDENTITY);
	shared_ptr<MslObject> authdata = data->getAuthData(encoder, format);
	EXPECT_FALSE(authdata->remove(KEY_IDENTITY).isNull());
	try {
		make_shared<UnauthenticatedAuthenticationData>(authdata);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslEncodingException& e) {
		EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
	}
}

TEST_F(UnauthenticatedAuthenticationDataTest, equalsIdentity)
{
	shared_ptr<UnauthenticatedAuthenticationData> dataA = make_shared<UnauthenticatedAuthenticationData>(IDENTITY + "A");
	shared_ptr<UnauthenticatedAuthenticationData> dataB = make_shared<UnauthenticatedAuthenticationData>(IDENTITY + "B");
	shared_ptr<EntityAuthenticationData> dataA2 = EntityAuthenticationData::create(ctx, MslTestUtils::toMslObject(encoder, dataA));

	EXPECT_EQ(*dataA, *dataA);

	EXPECT_NE(*dataA, *dataB);
	EXPECT_NE(*dataB, *dataA);

	EXPECT_EQ(*dataA, *dataA2);
	EXPECT_EQ(*dataA2, *dataA);
}

}}} // namespace netflix::msl::util
