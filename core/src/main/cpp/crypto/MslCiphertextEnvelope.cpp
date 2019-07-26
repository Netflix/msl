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

#include <crypto/MslCiphertextEnvelope.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <IllegalArgumentException.h>
#include <MslConstants.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <sstream>

using namespace std;
using netflix::msl::io::MslEncoderException;
using netflix::msl::io::MslEncoderFactory;
using netflix::msl::io::MslObject;
using netflix::msl::MslCryptoException;

namespace netflix {
namespace msl {
namespace crypto {

namespace {

const std::string KEY_VERSION = "version";
const std::string KEY_KEY_ID = "keyid";
const std::string KEY_CIPHERSPEC = "cipherspec";
const std::string KEY_IV = "iv";
const std::string KEY_CIPHERTEXT = "ciphertext";
const std::string KEY_SHA256 = "sha256";

MslCiphertextEnvelope parseEvelope(shared_ptr<MslObject> mo, const MslCiphertextEnvelope::Version& version)
{
    int v;
    std::string keyId;
    int cs;
    shared_ptr<ByteArray> iv;
    shared_ptr<ByteArray> ciphertext;

    if (version == MslCiphertextEnvelope::Version::V1) {
        try {
            v = MslCiphertextEnvelope::Version::V1;
            keyId = mo->getString(KEY_KEY_ID);
            cs = MslConstants::CipherSpec::INVALID;
            if (mo->has(KEY_IV))
                iv = mo->getBytes(KEY_IV);
            ciphertext = mo->getBytes(KEY_CIPHERTEXT);
            mo->getBytes(KEY_SHA256);  // easy way to throw if not there
        } catch (const MslEncoderException& e) {
            std::stringstream ss;
            ss << "ciphertext envelope " << mo;
            throw MslEncodingException(MslError::MSL_PARSE_ERROR, ss.str(), e);
        }
    }
    else if (version == MslCiphertextEnvelope::Version::V2) {
        try {
            v = mo->getInt(KEY_VERSION);
            if (v != MslCiphertextEnvelope::Version::V2) {
                std::stringstream ss;
                ss << "ciphertext envelope "  << mo;
                throw MslCryptoException(MslError::UNIDENTIFIED_CIPHERTEXT_ENVELOPE, ss.str());
            }
            keyId = "";
            cs = MslConstants::CipherSpec::fromString(mo->getString(KEY_CIPHERSPEC));
            if (cs == MslConstants::CipherSpec::INVALID)
                throw IllegalArgumentException("INVALID Cipherspec"); // go to catch below
            if (mo->has(KEY_IV))
                iv = mo->getBytes(KEY_IV);
            ciphertext = mo->getBytes(KEY_CIPHERTEXT);
        } catch (const IllegalArgumentException& e) {
            std::stringstream ss;
            ss << "ciphertext envelope " << mo;
            throw MslCryptoException(MslError::UNIDENTIFIED_CIPHERSPEC, ss.str(), e);
        } catch (const MslEncoderException& e) {
            std::stringstream ss;
            ss << "ciphertext envelope " << mo;
            throw MslEncodingException(MslError::MSL_PARSE_ERROR, ss.str(), e);
        }
    }
    else {
        std::stringstream ss;
        ss << "ciphertext envelope version " << version;
        throw MslCryptoException(MslError::UNSUPPORTED_CIPHERTEXT_ENVELOPE, ss.str());
    }
    return MslCiphertextEnvelope(MslCiphertextEnvelope::Version::valueOf(v),
            keyId, MslConstants::CipherSpec::valueOf(cs), iv, ciphertext);
}
} // anonymous namespace

// --- start MslCiphertextEnvelope::Version

const MslCiphertextEnvelope::Version MslCiphertextEnvelope::Version::V1(MslCiphertextEnvelope::Version::v1, "V1");
const MslCiphertextEnvelope::Version MslCiphertextEnvelope::Version::V2(MslCiphertextEnvelope::Version::v2, "V2");
const MslCiphertextEnvelope::Version MslCiphertextEnvelope::Version::INVALID(MslCiphertextEnvelope::Version::invalid, "INVALID");

// static
const std::vector<MslCiphertextEnvelope::Version>& MslCiphertextEnvelope::Version::getValues()
{
    static std::vector<Version> gValues;
    if (gValues.empty()) {
        gValues.push_back(V1);
        gValues.push_back(V2);
    }
    return gValues;
}

// --- end MslCiphertextEnvelope::Version

shared_ptr<ByteArray> MslCiphertextEnvelope::toMslEncoding(shared_ptr<io::MslEncoderFactory> encoder,
        const io::MslEncoderFormat& format) const
{
    shared_ptr<MslObject> mo = encoder->createObject();
    if (version_ == MslCiphertextEnvelope::Version::V1) {
        mo->put<std::string>(KEY_KEY_ID, keyId_);
        if (iv_)
            mo->put<shared_ptr<ByteArray>>(KEY_IV, iv_);
        mo->put<shared_ptr<ByteArray>>(KEY_CIPHERTEXT, ciphertext_);
        mo->put<std::string>(KEY_SHA256, "AA==");
    }
    else if (version_ == MslCiphertextEnvelope::Version::V2) {
        mo->put<int>(KEY_VERSION, version_);
        mo->put<std::string>(KEY_CIPHERSPEC, cipherSpec_);
        if (iv_)
            mo->put<shared_ptr<ByteArray>>(KEY_IV, iv_);
        mo->put<shared_ptr<ByteArray>>(KEY_CIPHERTEXT, ciphertext_);
    }
    else {
        std::stringstream ss;
        ss << "Ciphertext envelope version " << version_ << " encoding unsupported.";
        throw MslEncoderException(ss.str());
    }
    return encoder->encodeObject(mo, format);
}


// non-member functions

MslCiphertextEnvelope::Version getCiphertextEnvelopeVersion(shared_ptr<MslObject> mo)
{
    try {
        const int v = mo->getInt(KEY_VERSION);
        return MslCiphertextEnvelope::Version::valueOf(v);
    } catch (const MslEncoderException& e) {
        // If anything fails to parse, treat this as a version 1 envelope.
        return MslCiphertextEnvelope::Version::V1;
    } catch (const IllegalArgumentException& e) {
        std::stringstream ss;
        ss << "ciphertext envelope " << mo;
        throw MslCryptoException(MslError::UNIDENTIFIED_CIPHERTEXT_ENVELOPE, ss.str(), e);
    }
}

MslCiphertextEnvelope createMslCiphertextEnvelope(shared_ptr<MslObject> mo, const MslCiphertextEnvelope::Version& version)
{
    return parseEvelope(mo, version);
}

MslCiphertextEnvelope createMslCiphertextEnvelope(shared_ptr<MslObject> mo)
{
    return parseEvelope(mo, getCiphertextEnvelopeVersion(mo));
}


}}} // namespace netflix::msl::crypto
