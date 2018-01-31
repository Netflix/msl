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

#include <crypto/MslSignatureEnvelope.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <io/MslVariant.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <util/Base64.h>

using namespace std;
using netflix::msl::io::MslEncoderException;
using netflix::msl::io::MslEncoderFactory;
using netflix::msl::io::MslEncoderFormat;
using netflix::msl::io::MslObject;
using netflix::msl::io::Variant;

namespace netflix {
namespace msl {
namespace crypto {

namespace // anonymous
{

/** Key version. */
const std::string KEY_VERSION = "version";
/** Key algorithm. */
const std::string KEY_ALGORITHM = "algorithm";
/** Key signature. */
const std::string KEY_SIGNATURE = "signature";

} //namespace anonymous

// --- start MslSignatureEnvelope::Version

const MslSignatureEnvelope::Version MslSignatureEnvelope::Version::V1(MslSignatureEnvelope::Version::v1, "V1");
const MslSignatureEnvelope::Version MslSignatureEnvelope::Version::V2(MslSignatureEnvelope::Version::v2, "V2");
const MslSignatureEnvelope::Version MslSignatureEnvelope::Version::INVALID(MslSignatureEnvelope::Version::invalid, "INVALID");

// static
const std::vector<MslSignatureEnvelope::Version>& MslSignatureEnvelope::Version::getValues()
{
    static std::vector<Version> gValues;
    if (gValues.empty()) {
        gValues.push_back(V1);
        gValues.push_back(V2);
    }
    return gValues;
}

// static
MslSignatureEnvelope::Version MslSignatureEnvelope::Version::valueOf(int version)
{
    switch (version) {
        case 1: return V1;
        case 2: return V2;
        default: throw IllegalArgumentException("Unknown signature envelope version.");
    }
}

// --- end MslSignatureEnvelope::Version

shared_ptr<ByteArray> MslSignatureEnvelope::getBytes(shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& format) const
{
    if (version_ == Version::V1) {
        return signature_;
    }
    else if (version_ == Version::V2) {
        std::shared_ptr<MslObject> mo = encoder->createObject(std::map<std::string, Variant>());
        mo->put<int>(KEY_VERSION, version_);
        mo->put<std::string>(KEY_ALGORITHM, algorithm_.stringValue());
        mo->put<std::shared_ptr<ByteArray>>(KEY_SIGNATURE, signature_);
        return encoder->encodeObject(mo, format);
    }
    else {
        std::stringstream ss;
        ss << "Signature envelope version " << version_ << " encoding unsupported.";
        throw MslInternalException(ss.str());
    }
}

// static
MslSignatureEnvelope MslSignatureEnvelope::parse(shared_ptr<ByteArray> envelope,
        shared_ptr<MslEncoderFactory> encoder, const Version& version)
{
    // Parse envelope.
    if (version == Version::V1) {
        return MslSignatureEnvelope(envelope);
    }
    else if (version == Version::V2) {
        try {
            // We expect the byte representation to be a MSL object.
            shared_ptr<MslObject> envelopeMo = encoder->parseObject(envelope);

            // Verify version.
            try {
                const Version v = Version::valueOf(envelopeMo->getInt(KEY_VERSION));
                if (v != Version::V2) {
                    std::stringstream ss;
                    ss << "signature envelope " << envelopeMo;
                    throw MslCryptoException(MslError::UNSUPPORTED_SIGNATURE_ENVELOPE, ss.str());
                }
            } catch (const IllegalArgumentException& e) {
                std::stringstream ss;
                ss << "signature envelope " << envelopeMo;
                throw MslCryptoException(MslError::UNIDENTIFIED_SIGNATURE_ENVELOPE, ss.str(), e);
            }

            // Grab algorithm.
            MslConstants::SignatureAlgo algorithm;
            try {
                algorithm = MslConstants::SignatureAlgo::fromString(envelopeMo->getString(KEY_ALGORITHM));
            } catch (const IllegalArgumentException& e) {
                std::stringstream ss;
                ss << "signature envelope " << envelopeMo;
                throw MslCryptoException(MslError::UNIDENTIFIED_ALGORITHM, ss.str(), e);
            }

            // Grab signature.
            shared_ptr<ByteArray> signature = envelopeMo->getBytes(KEY_SIGNATURE);

            // Return the envelope.
            return MslSignatureEnvelope(algorithm, signature);
        } catch (const MslEncoderException& e) {
            std::stringstream ss;
            ss << "signature envelope " << util::Base64::encode(envelope);
            throw MslEncodingException(MslError::MSL_PARSE_ERROR, ss.str(), e);
        }
    }
    else {
        std::stringstream ss;
        ss << "signature envelope " << util::Base64::encode(envelope);
        throw MslCryptoException(MslError::UNSUPPORTED_SIGNATURE_ENVELOPE, ss.str());
    }
}

//static
MslSignatureEnvelope MslSignatureEnvelope::parse(shared_ptr<ByteArray> envelope, shared_ptr<MslEncoderFactory> encoder)
{
    // Attempt to convert this to a MSL object.
    shared_ptr<MslObject> envelopeMo = encoder->createObject();
    try {
        // If this is a MSL object, we expect the byte representation to be
        // decodable.
        envelopeMo = encoder->parseObject(envelope);
    } catch (const MslEncoderException& e) {
        // do nothing, leave envelopeMo empty.
    }

    // Determine the envelope version.
    //
    // If there is no MSL object, or there is no version field (as the
    // binary signature may coincidentally parse into a MSL object), then
    // this is a version 1 envelope.
    Version version;
    if (!envelopeMo || !envelopeMo->has(KEY_VERSION)) {
        version = Version::V1;
    } else {
        try {
            version = Version::valueOf(envelopeMo->getInt(KEY_VERSION));
        } catch (const MslEncoderException& e) {
            // There is a possibility that this is a version 1 envelope.
            version = Version::V1;
        } catch (const IllegalArgumentException& e) {
            // There is a possibility that this is a version 1 envelope.
            version = Version::V1;
        }
    }

    // FIXME: Why not just call parse(envelope, encoder, version) here?

    // Parse envelope.
    if (version == Version::V1) {
        return MslSignatureEnvelope(envelope);
    }
    else if (version == Version::V2) {
        try {
            const std::string algoStr = envelopeMo->getString(KEY_ALGORITHM);
            const MslConstants::SignatureAlgo algorithm = MslConstants::SignatureAlgo::fromString(algoStr);
            shared_ptr<ByteArray> signature = envelopeMo->getBytes(KEY_SIGNATURE);
            return MslSignatureEnvelope(algorithm, signature);
        } catch (const MslEncoderException& e) {
            // It is extremely unlikely but possible that this is a
            // version 1 envelope.
            return MslSignatureEnvelope(envelope);
        } catch (const IllegalArgumentException& e) {
            // It is extremely unlikely but possible that this is a
            // version 1 envelope.
            return MslSignatureEnvelope(envelope);
        }
    }
    else {
        std::stringstream ss;
        ss << "signature envelope " << util::Base64::encode(envelope);
        throw MslCryptoException(MslError::UNSUPPORTED_SIGNATURE_ENVELOPE, ss.str());
    }
}

}}} // namespace netflix::msl::crypto
