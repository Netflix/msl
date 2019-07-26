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

#include <keyx/KeyRequestData.h>
#include <gtest/gtest.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <MslEncodingException.h>
#include <MslKeyExchangeException.h>
#include <util/MockMslContext.h>
#include <util/MslContext.h>
#include <memory>
#include <string>

using netflix::msl::entityauth::EntityAuthenticationScheme;

using namespace std;
using namespace testing;
using namespace netflix::msl;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace keyx {

namespace {

/** Key key exchange scheme. */
const string KEY_SCHEME = "scheme";
/** Key key request data. */
const string KEY_KEYDATA = "keydata";

} // namespace anonymous

/**
 * Key request data unit tests.
 *
 * Successful calls to
 * {@link KeyRequestData#create(com.netflix.msl.util.MslContext, org.json.MslObject)}
 * covered in the individual key request data unit tests.
 */
class KeyRequestDataTest : public ::testing::Test
{
public:
    KeyRequestDataTest()
    : ctx(make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false))
    , encoder(ctx->getMslEncoderFactory())
    {}

protected:
    /** MSL context. */
    shared_ptr<MslContext> ctx;
    /** MSL encoder factory. */
    shared_ptr<MslEncoderFactory> encoder;
};

TEST_F(KeyRequestDataTest, noScheme)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_SCHEME + "x", KeyExchangeScheme::ASYMMETRIC_WRAPPED.name());
    mo->put(KEY_KEYDATA, encoder->createObject());

    try {
        KeyRequestData::create(ctx, mo);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(KeyRequestDataTest, noKeydata)
{
//    thrown.expect(MslEncodingException.class);
//    thrown.expectMslError(MslError.MSL_PARSE_ERROR);

    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_SCHEME, KeyExchangeScheme::ASYMMETRIC_WRAPPED.name());
    mo->put(KEY_KEYDATA + "x", encoder->createObject());

    try {
        KeyRequestData::create(ctx, mo);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
}

TEST_F(KeyRequestDataTest, unidentifiedScheme)
{
//    thrown.expect(MslKeyExchangeException.class);
//    thrown.expectMslError(MslError.UNIDENTIFIED_KEYX_SCHEME);

    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put<string>(KEY_SCHEME, "x");
    mo->put(KEY_KEYDATA, encoder->createObject());

    try {
        KeyRequestData::create(ctx, mo);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslKeyExchangeException& e) {
        EXPECT_EQ(MslError::UNIDENTIFIED_KEYX_SCHEME, e.getError());
    }
}

TEST_F(KeyRequestDataTest, keyxFactoryNotFound)
{
//    thrown.expect(MslKeyExchangeException.class);
//    thrown.expectMslError(MslError.KEYX_FACTORY_NOT_FOUND);

    shared_ptr<MockMslContext> ctx1 = make_shared<MockMslContext>(EntityAuthenticationScheme::PSK, false);
    ctx1->removeKeyExchangeFactories(KeyExchangeScheme::ASYMMETRIC_WRAPPED);
    shared_ptr<MslObject> mo = encoder->createObject();
    mo->put(KEY_SCHEME, KeyExchangeScheme::ASYMMETRIC_WRAPPED.name());
    mo->put(KEY_KEYDATA, encoder->createObject());

    try {
        KeyRequestData::create(ctx1, mo);
        ADD_FAILURE() << "Should have thrown.";
    } catch (const MslKeyExchangeException& e) {
        EXPECT_EQ(MslError::KEYX_FACTORY_NOT_FOUND, e.getError());
    }
}

}}} // namespace netflix::msl::keyx
