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

#include <entityauth/MockKeySetStore.h>
#include <entityauth/PresharedAuthenticationData.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <entityauth/PresharedAuthenticationFactory.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <Macros.h>
#include <MslEncodingException.h>
#include <MslEntityAuthException.h>
#include <memory>
#include <string>

#include <entityauth/MockPresharedAuthenticationFactory.h>
#include <util/MockAuthenticationUtils.h>
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
namespace util {

namespace {

/** Key entity identity. */
const string KEY_IDENTITY = "identity";

} // namespace anonymous

/**
 * Pre-shared keys entity authentication factory unit tests.
 */
class PresharedAuthenticationFactoryTest : public ::testing::Test
{
public:
	PresharedAuthenticationFactoryTest()
    : ENCODER_FORMAT(MslEncoderFormat::JSON)
    , ctx(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false))
    , encoder(ctx->getMslEncoderFactory())
    , authutils(make_shared<MockAuthenticationUtils>())
    {
	    shared_ptr<MockKeySetStore> store = make_shared<MockKeySetStore>();
        store->addKeys(MockPresharedAuthenticationFactory::PSK_ESN,
                MockPresharedAuthenticationFactory::KPE,
                MockPresharedAuthenticationFactory::KPH,
                MockPresharedAuthenticationFactory::KPW);
        factory = make_shared<PresharedAuthenticationFactory>(store, authutils);
        ctx->addEntityAuthenticationFactory(factory);
    }
	~PresharedAuthenticationFactoryTest() { authutils->reset(); }
protected:
    /** MSL encoder format. */
    const MslEncoderFormat ENCODER_FORMAT;
    /** MSL context. */
    shared_ptr<MockMslContext> ctx;
    /** MSL encoder factory-> */
    shared_ptr<MslEncoderFactory> encoder;
    /** Authentication utilities. */
    shared_ptr<MockAuthenticationUtils> authutils;
    /** Entity authentication factory-> */
    shared_ptr<EntityAuthenticationFactory> factory;
};

TEST_F(PresharedAuthenticationFactoryTest, createData)
{
    shared_ptr<PresharedAuthenticationData> data = make_shared<PresharedAuthenticationData>(MockPresharedAuthenticationFactory::PSK_ESN);
    shared_ptr<MslObject> entityAuthMo = data->getAuthData(encoder, ENCODER_FORMAT);

    shared_ptr<EntityAuthenticationData> authdata = factory->createData(ctx, entityAuthMo);
    EXPECT_TRUE(authdata);
    EXPECT_TRUE(instanceof<PresharedAuthenticationData>(authdata.get()));

    shared_ptr<MslObject> dataMo = MslTestUtils::toMslObject(encoder, data);
    shared_ptr<MslObject> authdataMo = MslTestUtils::toMslObject(encoder, authdata);
    EXPECT_EQ(*dataMo, *authdataMo);
}

TEST_F(PresharedAuthenticationFactoryTest, encodeException)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<PresharedAuthenticationData> data = make_shared<PresharedAuthenticationData>(MockPresharedAuthenticationFactory::PSK_ESN);
    shared_ptr<MslObject> entityAuthMo = data->getAuthData(encoder, ENCODER_FORMAT);
    entityAuthMo->remove(KEY_IDENTITY);
    try {
        factory->createData(ctx, entityAuthMo);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(PresharedAuthenticationFactoryTest, cryptoContext)
{
    shared_ptr<PresharedAuthenticationData> data = make_shared<PresharedAuthenticationData>(MockPresharedAuthenticationFactory::PSK_ESN);
    shared_ptr<ICryptoContext> cryptoContext = factory->getCryptoContext(ctx, data);
    EXPECT_TRUE(cryptoContext);
}

TEST_F(PresharedAuthenticationFactoryTest, unknownEsn)
{
//    thrown.expect(MslEntityAuthException.class);
//    thrown.expectMslError(MslError.ENTITY_NOT_FOUND);

    shared_ptr<PresharedAuthenticationData> data = make_shared<PresharedAuthenticationData>(MockPresharedAuthenticationFactory::PSK_ESN2);
    try {
        factory->getCryptoContext(ctx, data);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEntityAuthException& e) {
        EXPECT_EQ(MslError::ENTITY_NOT_FOUND, e.getError());
    }
}

TEST_F(PresharedAuthenticationFactoryTest, revoked)
{
//    thrown.expect(MslEntityAuthException.class);
//    thrown.expectMslError(MslError.ENTITY_REVOKED);

    authutils->revokeEntity(MockPresharedAuthenticationFactory::PSK_ESN);
    shared_ptr<PresharedAuthenticationData> data = make_shared<PresharedAuthenticationData>(MockPresharedAuthenticationFactory::PSK_ESN);
    try {
        factory->getCryptoContext(ctx, data);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEntityAuthException& e) {
        EXPECT_EQ(MslError::ENTITY_REVOKED, e.getError());
    }
}

}}} // namespace netflix::msl::util
