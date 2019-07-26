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
#include <entityauth/EccAuthenticationData.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslEntityAuthException.h>
#include <MslError.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslEncoderUtils.h>
#include <io/MslObject.h>
#include <util/MockMslContext.h>
#include <util/MslContext.h>
#include <util/MslTestUtils.h>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace entityauth {

namespace {
/** Key entity authentication scheme. */
const string KEY_SCHEME = "scheme";
/** Key entity authentication data. */
const string KEY_AUTHDATA = "authdata";
/** Key entity identity. */
const string KEY_IDENTITY = "identity";
/** Key public key ID. */
const string KEY_PUBKEY_ID = "pubkeyid";
} // namespace anonymous

/**
 * ECC entity authentication data unit tests.
 */
class DISABLED_EccAuthenticationDataTest : public ::testing::Test
{
public:
	virtual ~DISABLED_EccAuthenticationDataTest() {}

	DISABLED_EccAuthenticationDataTest()
		: format(MslEncoderFormat::JSON)
		, ctx(make_shared<MockMslContext>(EntityAuthenticationScheme::X509, false))
		, encoder(ctx->getMslEncoderFactory())
	{}

protected:
	const MslEncoderFormat format;
    /** MSL context. */
    shared_ptr<MslContext> ctx;
    /** MSL encoder factory. */
	shared_ptr<MslEncoderFactory> encoder;
};


// FIXME TODO
TEST_F(DISABLED_EccAuthenticationDataTest, todo)
{
    EXPECT_TRUE(false) << "This test suite needs to be implemented";
}

#if 0
TEST_F(DISABLED_EccAuthenticationDataTest, ctors)
{
        shared_ptr<EccAuthenticationData> data = make_shared<EccAuthenticationData>(MockEccAuthenticationFactory::ECC_ESN, MockEccAuthenticationFactory::ECC_PUBKEY_ID);
        EXPECT_EQ(MockEccAuthenticationFactory::ECC_ESN, data.getIdentity());
        EXPECT_EQ(MockEccAuthenticationFactory::ECC_PUBKEY_ID, data.getPublicKeyId());
        EXPECT_EQ(EntityAuthenticationScheme.ECC, data.getScheme());
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(authdata);
        final byte[] encode = data.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);

        final EccAuthenticationData moData = new EccAuthenticationData(authdata);
        EXPECT_EQ(data.getIdentity(), moData.getIdentity());
        EXPECT_EQ(data.getPublicKeyId(), moData.getPublicKeyId());
        EXPECT_EQ(data.getScheme(), moData.getScheme());
        final MslObject moAuthdata = moData.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(moAuthdata);
        assertTrue(MslEncoderUtils.equalObjects(authdata, moAuthdata));
        final byte[] moEncode = moData.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        EXPECT_EQ(encode, moEncode);
    }

TEST_F(DISABLED_EccAuthenticationDataTest, mslObject)
{
        final EccAuthenticationData data = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
        final MslObject mo = MslTestUtils.toMslObject(encoder, data);
        EXPECT_EQ(EntityAuthenticationScheme.ECC.toString(), mo.getString(KEY_SCHEME));
        final MslObject authdata = mo.getMslObject(KEY_AUTHDATA, encoder);
        EXPECT_EQ(MockEccAuthenticationFactory.ECC_ESN, authdata.getString(KEY_IDENTITY));
        EXPECT_EQ(MockEccAuthenticationFactory.ECC_PUBKEY_ID, authdata.get(KEY_PUBKEY_ID));
    }

TEST_F(DISABLED_EccAuthenticationDataTest, create)
{
        final EccAuthenticationData data = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
        final byte[] encode = data.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = MslTestUtils.toMslObject(encoder, data);
        final EntityAuthenticationData entitydata = EntityAuthenticationData.create(ctx, mo);
        assertNotNull(entitydata);
        assertTrue(entitydata instanceof EccAuthenticationData);

        final EccAuthenticationData moData = (EccAuthenticationData)entitydata;
        EXPECT_EQ(data.getIdentity(), moData.getIdentity());
        EXPECT_EQ(data.getPublicKeyId(), moData.getPublicKeyId());
        EXPECT_EQ(data.getScheme(), moData.getScheme());
        final MslObject moAuthdata = moData.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(moAuthdata);
        assertTrue(MslEncoderUtils.equalObjects(data.getAuthData(encoder, ENCODER_FORMAT), moAuthdata));
        final byte[] moEncode = moData.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        EXPECT_EQ(encode, moEncode);
    }

TEST_F(DISABLED_EccAuthenticationDataTest, missingIdentity)
{
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final EccAuthenticationData data = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.remove(KEY_IDENTITY);
        new EccAuthenticationData(authdata);
    }

TEST_F(DISABLED_EccAuthenticationDataTest, missingPubkeyId)
{
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final EccAuthenticationData data = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.remove(KEY_PUBKEY_ID);
        new EccAuthenticationData(authdata);
    }

TEST_F(DISABLED_EccAuthenticationDataTest, equalsIdentity)
{
        final String identityA = MockEccAuthenticationFactory.ECC_ESN + "A";
        final String identityB = MockEccAuthenticationFactory.ECC_ESN + "B";
        final EccAuthenticationData dataA = new EccAuthenticationData(identityA, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
        final EccAuthenticationData dataB = new EccAuthenticationData(identityB, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
        final EntityAuthenticationData dataA2 = EntityAuthenticationData.create(ctx, MslTestUtils.toMslObject(encoder, dataA));

        assertTrue(dataA.equals(dataA));
        EXPECT_EQ(dataA.hashCode(), dataA.hashCode());

        assertFalse(dataA.equals(dataB));
        assertFalse(dataB.equals(dataA));
        assertTrue(dataA.hashCode() != dataB.hashCode());

        assertTrue(dataA.equals(dataA2));
        assertTrue(dataA2.equals(dataA));
        EXPECT_EQ(dataA.hashCode(), dataA2.hashCode());
    }

TEST_F(DISABLED_EccAuthenticationDataTest, equalsPubKeyId)
{
        final String pubkeyidA = MockEccAuthenticationFactory.ECC_PUBKEY_ID + "A";
        final String pubkeyidB = MockEccAuthenticationFactory.ECC_PUBKEY_ID + "B";
        final EccAuthenticationData dataA = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, pubkeyidA);
        final EccAuthenticationData dataB = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, pubkeyidB);
        final EntityAuthenticationData dataA2 = EntityAuthenticationData.create(ctx, MslTestUtils.toMslObject(encoder, dataA));

        assertTrue(dataA.equals(dataA));
        EXPECT_EQ(dataA.hashCode(), dataA.hashCode());

        assertFalse(dataA.equals(dataB));
        assertFalse(dataB.equals(dataA));
        assertTrue(dataA.hashCode() != dataB.hashCode());

        assertTrue(dataA.equals(dataA2));
        assertTrue(dataA2.equals(dataA));
        EXPECT_EQ(dataA.hashCode(), dataA2.hashCode());
}
#endif

}}} // namespace netflix::msl::entityauth
