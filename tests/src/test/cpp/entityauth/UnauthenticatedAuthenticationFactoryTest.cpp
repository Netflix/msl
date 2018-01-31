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

#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslEntityAuthException.h>
#include <MslError.h>
#include <crypto/ICryptoContext.h>
#include <entityauth/UnauthenticatedAuthenticationData.h>
#include <entityauth/UnauthenticatedAuthenticationFactory.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslEncoderUtils.h>
#include <io/MslObject.h>
#include <memory>

#include <gtest/gtest.h>
#include <util/MockAuthenticationUtils.h>
#include <util/MockMslContext.h>
#include <util/MslTestUtils.h>

using namespace std;
using namespace testing;
using namespace netflix::msl::crypto;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
typedef vector<uint8_t> ByteArray;
namespace entityauth {

namespace {
/** Key entity identity. */
const string KEY_IDENTITY = "identity";

const string UNAUTHENTICATED_ESN = "MOCKUNAUTH-ESN";
} // namespace anonymous

/**
 * Unauthenticated authentication factory unit tests.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class UnauthenticatedAuthenticationFactoryTest : public ::testing::Test
{
public:
	UnauthenticatedAuthenticationFactoryTest()
		: ctx(make_shared<MockMslContext>(EntityAuthenticationScheme::NONE, false))
		, encoder(ctx->getMslEncoderFactory())
		, format(MslEncoderFormat::JSON)
		, authutils(make_shared<MockAuthenticationUtils>())
		, factory(make_shared<UnauthenticatedAuthenticationFactory>(authutils))
	{
		ctx->addEntityAuthenticationFactory(factory);
	}

protected:
    /** MSL context. */
	shared_ptr<MockMslContext> ctx;
    /** MSL encoder factory. */
	shared_ptr<MslEncoderFactory> encoder;
	/** MSL encoder format. */
	const MslEncoderFormat format;
    /** Authentication utilities. */
    shared_ptr<MockAuthenticationUtils> authutils;
    /** Entity authentication factory. */
    shared_ptr<EntityAuthenticationFactory> factory;
};

TEST_F(UnauthenticatedAuthenticationFactoryTest, createData)
{
	shared_ptr<UnauthenticatedAuthenticationData> data = make_shared<UnauthenticatedAuthenticationData>(UNAUTHENTICATED_ESN);
	shared_ptr<MslObject> entityAuthMo = data->getAuthData(encoder, format);

	shared_ptr<EntityAuthenticationData> authdata = factory->createData(ctx, entityAuthMo);
	EXPECT_TRUE(authdata);
	EXPECT_TRUE(instanceof<UnauthenticatedAuthenticationData>(authdata.get()));

	shared_ptr<MslObject> dataMo = MslTestUtils::toMslObject(encoder, data);
	shared_ptr<MslObject> authdataMo = MslTestUtils::toMslObject(encoder, authdata);
	EXPECT_TRUE(MslEncoderUtils::equalObjects(dataMo, authdataMo));
}

TEST_F(UnauthenticatedAuthenticationFactoryTest, encodeException)
{
	shared_ptr<UnauthenticatedAuthenticationData> data = make_shared<UnauthenticatedAuthenticationData>(UNAUTHENTICATED_ESN);
	shared_ptr<MslObject> entityAuthMo = data->getAuthData(encoder, format);
	EXPECT_FALSE(entityAuthMo->remove(KEY_IDENTITY).isNull());
	try {
		factory->createData(ctx, entityAuthMo);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslEncodingException& e) {
		EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
	}
}

TEST_F(UnauthenticatedAuthenticationFactoryTest, cryptoContext)
{
	shared_ptr<UnauthenticatedAuthenticationData> data = make_shared<UnauthenticatedAuthenticationData>(UNAUTHENTICATED_ESN);
	shared_ptr<ICryptoContext> cryptoContext = factory->getCryptoContext(ctx, data);
	EXPECT_TRUE(cryptoContext);
}

TEST_F(UnauthenticatedAuthenticationFactoryTest, notPermitted)
{
    authutils->disallowScheme(UNAUTHENTICATED_ESN, EntityAuthenticationScheme::NONE);
	shared_ptr<UnauthenticatedAuthenticationData> data = make_shared<UnauthenticatedAuthenticationData>(UNAUTHENTICATED_ESN);
	try {
		factory->getCryptoContext(ctx, data);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslEntityAuthException& e) {
		EXPECT_EQ(MslError::INCORRECT_ENTITYAUTH_DATA, e.getError());
	}
}

TEST_F(UnauthenticatedAuthenticationFactoryTest, revoked)
{
	authutils->revokeEntity(UNAUTHENTICATED_ESN);
	shared_ptr<UnauthenticatedAuthenticationData> data = make_shared<UnauthenticatedAuthenticationData>(UNAUTHENTICATED_ESN);
	try {
		factory->getCryptoContext(ctx, data);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslEntityAuthException& e) {
		EXPECT_EQ(MslError::ENTITY_REVOKED, e.getError());
	}
}

}}} // namespace netflix::msl::entityauth
