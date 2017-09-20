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
#include <crypto/MslCiphertextEnvelope.h>
#include <io/DefaultMslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>

using namespace netflix::msl::io;
using namespace std;

namespace netflix {
namespace msl {
namespace crypto {

namespace {
const string KEY_VERSION = "version";
const string KEY_KEY_ID = "keyid";
const string KEY_CIPHERSPEC = "cipherspec";
const string KEY_IV = "iv";
const string KEY_CIPHERTEXT = "ciphertext";
const string KEY_SHA256 = "sha256";
}

class MslCiphertextEnvelopeTest : public ::testing::Test
{
public:
    MslCiphertextEnvelopeTest() : keyId("keyId") {
        iv->push_back(1);
        iv->push_back(2);
        iv->push_back(3);
        ciphertext->push_back(11);
        ciphertext->push_back(22);
        ciphertext->push_back(33);
    }
    const string keyId;
    shared_ptr<ByteArray> sha = make_shared<ByteArray>();
    shared_ptr<ByteArray> iv = make_shared<ByteArray>();
    shared_ptr<ByteArray> ciphertext = make_shared<ByteArray>();
};

TEST_F(MslCiphertextEnvelopeTest, GetCiphertextEnvelopeVersion)
{
    shared_ptr<MslObject> mo = make_shared<MslObject>();

    // defaults to V1 if unknown
    EXPECT_EQ(MslCiphertextEnvelope::Version::V1, getCiphertextEnvelopeVersion(mo));

    mo->put<int>(KEY_VERSION, MslCiphertextEnvelope::Version::V1);
    EXPECT_EQ(MslCiphertextEnvelope::Version::V1, getCiphertextEnvelopeVersion(mo));

    mo->put<int>(KEY_VERSION, MslCiphertextEnvelope::Version::V2);
    EXPECT_EQ(MslCiphertextEnvelope::Version::V2, getCiphertextEnvelopeVersion(mo));
}

TEST_F(MslCiphertextEnvelopeTest, Generic)
{
    const MslCiphertextEnvelope::Version version = MslCiphertextEnvelope::Version::V2;
    const MslConstants::CipherSpec cipherSpec = MslConstants::CipherSpec::AESWrap;
    const MslCiphertextEnvelope mce(version, keyId, cipherSpec, iv, ciphertext);
    EXPECT_EQ(version, mce.getVersion());
    EXPECT_EQ(keyId, mce.getKeyId());
    EXPECT_EQ(cipherSpec, mce.getCipherSpec());
    EXPECT_EQ(*iv, *mce.getIv());
    EXPECT_EQ(*ciphertext, *mce.getCiphertext());
}

TEST_F(MslCiphertextEnvelopeTest, Version1)
{
    const MslCiphertextEnvelope mce(keyId, iv, ciphertext);
    EXPECT_EQ(keyId, mce.getKeyId());
    EXPECT_EQ(MslConstants::CipherSpec::INVALID, mce.getCipherSpec());
    EXPECT_EQ(*iv, *mce.getIv());
    EXPECT_EQ(*ciphertext, *mce.getCiphertext());
    EXPECT_EQ(MslCiphertextEnvelope::Version::V1, mce.getVersion());
}

TEST_F(MslCiphertextEnvelopeTest, Version2)
{
    const string keyId = "keyId";
    const MslCiphertextEnvelope mce(MslConstants::CipherSpec::AESWrap, iv, ciphertext);
    EXPECT_EQ("", mce.getKeyId());
    EXPECT_EQ(MslConstants::CipherSpec::AESWrap, mce.getCipherSpec());
    EXPECT_EQ(*iv, *mce.getIv());
    EXPECT_EQ(*ciphertext, *mce.getCiphertext());
    EXPECT_EQ(MslCiphertextEnvelope::Version::V2, mce.getVersion());
}

TEST_F(MslCiphertextEnvelopeTest, CreateMslCiphertextEnvelopeV1)
{
    // set up the MslObject from which to create the MslCiphertextEnvelope
    const MslCiphertextEnvelope::Version ver1 = MslCiphertextEnvelope::Version::V1;
    shared_ptr<MslObject> mo = make_shared<MslObject>();
    mo->put<int>(KEY_VERSION, MslCiphertextEnvelope::Version::V2); // will be ignored
    mo->put<string>(KEY_KEY_ID, keyId);
    mo->put<string>(KEY_CIPHERSPEC, MslConstants::CipherSpec::AESWrap); // will be ignored
    mo->put<shared_ptr<ByteArray>>(KEY_IV, iv);
    mo->put<shared_ptr<ByteArray>>(KEY_CIPHERTEXT, ciphertext);
    mo->put<shared_ptr<ByteArray>>(KEY_SHA256, sha);

    // happy
    MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver1);
    EXPECT_EQ(ver1, mce.getVersion());
    EXPECT_EQ(keyId, mce.getKeyId());
    EXPECT_EQ(MslConstants::CipherSpec::INVALID, mce.getCipherSpec());
    EXPECT_EQ(*iv, *mce.getIv());
    EXPECT_EQ(*ciphertext, *mce.getCiphertext());

    // missing keyId
    mo->remove(KEY_KEY_ID);
    try {
        MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver1);
        ADD_FAILURE() << "createMslCiphertextEnvelope should have thrown";
    }
    catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
    mo->put<string>(KEY_KEY_ID, keyId);
    EXPECT_NO_THROW({MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver1);});

    // missing ciphertext
    mo->remove(KEY_CIPHERTEXT);
    try {
        MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver1);
        ADD_FAILURE() << "createMslCiphertextEnvelope should have thrown";
    }
    catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
    mo->put<shared_ptr<ByteArray>>(KEY_CIPHERTEXT, ciphertext);
    EXPECT_NO_THROW({MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver1);});

    // missing sha
    mo->remove(KEY_SHA256);
    try {
        MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver1);
        ADD_FAILURE() << "createMslCiphertextEnvelope should have thrown";
    }
    catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
    mo->put<shared_ptr<ByteArray>>(KEY_SHA256, sha);
    EXPECT_NO_THROW({MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver1);});

    // missing iv
    mo->remove(KEY_IV);
    EXPECT_NO_THROW({MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver1);});
    MslCiphertextEnvelope mceNoIv = createMslCiphertextEnvelope(mo, ver1);
    EXPECT_FALSE(mceNoIv.getIv());
    EXPECT_EQ(ver1, mceNoIv.getVersion());
    mo->put<shared_ptr<ByteArray>>(KEY_IV, iv);

    // happy with version detection
    mo->put<int>(KEY_VERSION, ver1);
    MslCiphertextEnvelope mce1 = createMslCiphertextEnvelope(mo);
    EXPECT_EQ(ver1, mce1.getVersion());
    EXPECT_EQ(keyId, mce1.getKeyId());
    EXPECT_EQ(MslConstants::CipherSpec::INVALID, mce1.getCipherSpec());
    EXPECT_EQ(*iv, *mce1.getIv());
    EXPECT_EQ(*ciphertext, *mce1.getCiphertext());
}

TEST_F(MslCiphertextEnvelopeTest, CreateMslCiphertextEnvelopeV2)
{
    // set up the MslObject from which to create the MslCiphertextEnvelope
    const MslCiphertextEnvelope::Version ver2 = MslCiphertextEnvelope::Version::V2;
    shared_ptr<MslObject> mo = make_shared<MslObject>();
    mo->put<int>(KEY_VERSION, ver2); // must be V2
    mo->put<string>(KEY_KEY_ID, keyId); // ignored, set to empty
    mo->put<string>(KEY_CIPHERSPEC, MslConstants::CipherSpec::AESWrap); // required
    mo->put<shared_ptr<ByteArray>>(KEY_IV, iv); // optional
    mo->put<shared_ptr<ByteArray>>(KEY_CIPHERTEXT, ciphertext); // required
    mo->put<shared_ptr<ByteArray>>(KEY_SHA256, sha); // ignored

    // happy
    MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver2);
    EXPECT_EQ(ver2, mce.getVersion());
    EXPECT_EQ("", mce.getKeyId());
    EXPECT_EQ(MslConstants::CipherSpec::AESWrap, mce.getCipherSpec());
    EXPECT_EQ(*iv, *mce.getIv());
    EXPECT_EQ(*ciphertext, *mce.getCiphertext());

    // bad version
    mo->put<int>(KEY_VERSION, MslCiphertextEnvelope::Version::V1);
    try {
        MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver2);
        ADD_FAILURE() << "createMslCiphertextEnvelope should have thrown";
    }
    catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::UNIDENTIFIED_CIPHERTEXT_ENVELOPE, e.getError());
    }
    mo->put<int>(KEY_VERSION, ver2);
    EXPECT_NO_THROW({MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver2);});

    // missing version
    mo->remove(KEY_VERSION);
    try {
        MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver2);
        ADD_FAILURE() << "createMslCiphertextEnvelope should have thrown";
    }
    catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
    mo->put<int>(KEY_VERSION, ver2);
    EXPECT_NO_THROW({MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver2);});

    // missing keyId (noop)
    mo->remove(KEY_KEY_ID);
    EXPECT_NO_THROW({MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver2);});

    // missing cipherspec
    mo->remove(KEY_CIPHERSPEC);
    try {
        MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver2);
        ADD_FAILURE() << "createMslCiphertextEnvelope should have thrown";
    }
    catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
    mo->put<string>(KEY_CIPHERSPEC, MslConstants::CipherSpec::AESWrap);
    EXPECT_NO_THROW({MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver2);});

    // invalid cipherspec 1
    mo->put<string>(KEY_CIPHERSPEC, "foobar");
    try {
        MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver2);
        ADD_FAILURE() << "createMslCiphertextEnvelope should have thrown";
    }
    catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::UNIDENTIFIED_CIPHERSPEC, e.getError());
    }
    mo->put<string>(KEY_CIPHERSPEC, MslConstants::CipherSpec::AESWrap);
    EXPECT_NO_THROW({MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver2);});

    // invalid cipherspec 2
    mo->put<string>(KEY_CIPHERSPEC, MslConstants::CipherSpec::INVALID);
    try {
        MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver2);
        ADD_FAILURE() << "createMslCiphertextEnvelope should have thrown";
    }
    catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::UNIDENTIFIED_CIPHERSPEC, e.getError());
    }
    mo->put<string>(KEY_CIPHERSPEC, MslConstants::CipherSpec::AESWrap);
    EXPECT_NO_THROW({MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver2);});

    // missing iv
    mo->remove(KEY_IV);
    EXPECT_NO_THROW({MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver2);});
    MslCiphertextEnvelope mceNoIv = createMslCiphertextEnvelope(mo, ver2);
    EXPECT_FALSE(mceNoIv.getIv());
    EXPECT_EQ(ver2, mceNoIv.getVersion());
    mo->put<shared_ptr<ByteArray>>(KEY_IV, iv);

    // missing ciphertext
    mo->remove(KEY_CIPHERTEXT);
    try {
        MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver2);
        ADD_FAILURE() << "createMslCiphertextEnvelope should have thrown";
    }
    catch (const MslEncodingException& e) {
        EXPECT_EQ(MslError::MSL_PARSE_ERROR, e.getError());
    }
    mo->put<shared_ptr<ByteArray>>(KEY_CIPHERTEXT, ciphertext);
    EXPECT_NO_THROW({MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, ver2);});

    // happy with version detection
    mo->put<int>(KEY_VERSION, ver2);
    MslCiphertextEnvelope mce1 = createMslCiphertextEnvelope(mo);
    EXPECT_EQ(ver2, mce1.getVersion());
    EXPECT_EQ("", mce1.getKeyId());
    EXPECT_EQ(MslConstants::CipherSpec::AESWrap, mce1.getCipherSpec());
    EXPECT_EQ(*iv, *mce1.getIv());
    EXPECT_EQ(*ciphertext, *mce1.getCiphertext());
}

TEST_F(MslCiphertextEnvelopeTest, CreateMslCiphertextEnvelopebadVersion)
{
    shared_ptr<MslObject> mo = make_shared<MslObject>();
    mo->put<int>(KEY_VERSION, MslCiphertextEnvelope::Version::V2); // must be V2
    mo->put<string>(KEY_KEY_ID, keyId); // ignored, set to empty
    mo->put<string>(KEY_CIPHERSPEC, MslConstants::CipherSpec::AESWrap); // required
    mo->put<shared_ptr<ByteArray>>(KEY_IV, iv); // optional
    mo->put<shared_ptr<ByteArray>>(KEY_CIPHERTEXT, ciphertext); // required
    mo->put<shared_ptr<ByteArray>>(KEY_SHA256, sha); // ignored

    try {
        MslCiphertextEnvelope mce = createMslCiphertextEnvelope(mo, MslCiphertextEnvelope::Version::INVALID);
        ADD_FAILURE() << "createMslCiphertextEnvelope should have thrown";
    }
    catch (const MslCryptoException& e) {
        EXPECT_EQ(MslError::UNSUPPORTED_CIPHERTEXT_ENVELOPE, e.getError());
    }
}

// FIXME: This is an error-prone test because there is no guarantee of how
// a JSON encoding might be constructed or formatted.
TEST_F(MslCiphertextEnvelopeTest, ToMslEncoding)
{
    shared_ptr<MslObject> mo1 = make_shared<MslObject>();
    mo1->put<int>(KEY_VERSION, MslCiphertextEnvelope::Version::V1);
    mo1->put<string>(KEY_KEY_ID, keyId);
    mo1->put<string>(KEY_CIPHERSPEC, MslConstants::CipherSpec::AESWrap);
    mo1->put<shared_ptr<ByteArray>>(KEY_IV, iv);
    mo1->put<shared_ptr<ByteArray>>(KEY_CIPHERTEXT, ciphertext);
    mo1->put<shared_ptr<ByteArray>>(KEY_SHA256, sha);

    // V1 with IV
    shared_ptr<MslEncoderFactory> mef = make_shared<DefaultMslEncoderFactory>();
    shared_ptr<ByteArray> ba;
    ba = createMslCiphertextEnvelope(mo1).toMslEncoding(mef, io::MslEncoderFormat::JSON);
    EXPECT_EQ(
        "{\"ciphertext\":\"CxYh\",\"iv\":\"AQID\",\"keyid\":\"keyId\",\"sha256\":\"AA==\"}",
        string(ba->begin(), ba->end())
    );

    // V1 without IV
    mo1->remove(KEY_IV);
    ba = createMslCiphertextEnvelope(mo1).toMslEncoding(mef, io::MslEncoderFormat::JSON);
    EXPECT_EQ(
        "{\"ciphertext\":\"CxYh\",\"keyid\":\"keyId\",\"sha256\":\"AA==\"}",
        string(ba->begin(), ba->end())
    );

    shared_ptr<MslObject> mo2 = mef->createObject();
    mo2->put<int>(KEY_VERSION, MslCiphertextEnvelope::Version::V2);
    mo2->put<string>(KEY_KEY_ID, keyId);
    mo2->put<string>(KEY_CIPHERSPEC, MslConstants::CipherSpec::AESWrap);
    mo2->put<shared_ptr<ByteArray>>(KEY_IV, iv);
    mo2->put<shared_ptr<ByteArray>>(KEY_CIPHERTEXT, ciphertext);
    mo2->put<shared_ptr<ByteArray>>(KEY_SHA256, sha);

    // V2 with IV
    ba = createMslCiphertextEnvelope(mo2).toMslEncoding(mef, io::MslEncoderFormat::JSON);
    EXPECT_EQ(
        "{\"cipherspec\":\"AESWrap\",\"ciphertext\":\"CxYh\",\"iv\":\"AQID\",\"version\":2}",
        string(ba->begin(), ba->end())
    );

    // V2 without IV
    mo2->remove(KEY_IV);
    ba = createMslCiphertextEnvelope(mo2).toMslEncoding(mef, io::MslEncoderFormat::JSON);
    EXPECT_EQ(
        "{\"cipherspec\":\"AESWrap\",\"ciphertext\":\"CxYh\",\"version\":2}",
        string(ba->begin(), ba->end())
    );

    // bad version
    try {
        createMslCiphertextEnvelope(mo2).toMslEncoding(mef, io::MslEncoderFormat::INVALID);
        ADD_FAILURE() << "createMslCiphertextEnvelope should have thrown";
    }
    catch(const MslEncoderException& e) {
        EXPECT_STREQ("Unsupported encoder format: INVALID.", e.what());
    }
}

}}} // namespace netflix::msl::crypto
