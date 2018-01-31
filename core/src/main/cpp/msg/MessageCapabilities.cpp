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

#include <msg/MessageCapabilities.h>
#include <MslConstants.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <io/MslArray.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <util/MslUtils.h>
#include <algorithm>
#include <iosfwd>
#include <vector>

using namespace std;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace msg {

namespace {
    /** Key compression algorithms. */
    const string KEY_COMPRESSION_ALGOS = "compressionalgos";
    /** Key languages. */
    const string KEY_LANGUAGES = "languages";
    /** Key encoder formats. */
    const string KEY_ENCODER_FORMATS = "encoderformats";

//    Variant algoToVariant(const MslConstants::CompressionAlgorithm& x) { return VariantFactory::create(x.toString()); }
//    Variant stringToVariant(const std::string& x) { return VariantFactory::create(x); }
//    Variant formatToVariant(const io::MslEncoderFormat& x) { return VariantFactory::create(x.name()); }

    template <typename T> void intersect(const set<T>& a, const set<T>& b, set<T>& c) {
        set_intersection(a.begin(), a.end(), b.begin(), b.end(), inserter(c, c.begin()));
    }
}

// static
shared_ptr<MessageCapabilities> MessageCapabilities::intersection(shared_ptr<MessageCapabilities> mc1,
        shared_ptr<MessageCapabilities> mc2)
{
	if (!mc1 || !mc2)
		return shared_ptr<MessageCapabilities>();

    // Compute the intersection of compression algorithms.
    set<MslConstants::CompressionAlgorithm> compressionAlgos;
    intersect(mc1->compressionAlgos_, mc2->compressionAlgos_, compressionAlgos);

    // Compute the intersection of languages. This contents of the lists have
    // a user-determined order so we cannot sort for efficiency.
    const vector<string>& smaller =
        (mc1->languages_.size() < mc2->languages_.size()) ? mc1->languages_ : mc2->languages_;
    const vector<string>& larger =
        (mc1->languages_.size() < mc2->languages_.size()) ? mc2->languages_ : mc1->languages_;
    vector<string> languages;
    for (vector<string>::const_iterator it = smaller.begin(); it != smaller.end(); ++it) {
        for (vector<string>::const_iterator jt = larger.begin(); jt != larger.end(); ++jt) {
            if (*jt == *it)
                languages.push_back(*it);
        }
    }

    // Compute the intersection of encoder formats.
    set<MslEncoderFormat> encoderFormats;
    intersect(mc1->encoderFormats_, mc2->encoderFormats_, encoderFormats);

    return make_shared<MessageCapabilities>(compressionAlgos, languages, encoderFormats);
}

MessageCapabilities::MessageCapabilities(
        const set<MslConstants::CompressionAlgorithm>& compressionAlgos,
        const vector<string>& languages,
        const set<MslEncoderFormat>& encoderFormats)
: compressionAlgos_(compressionAlgos)
, languages_(languages)
, encoderFormats_(encoderFormats)
{
}

MessageCapabilities::MessageCapabilities(shared_ptr<MslObject> capabilitiesMo)
{
    try {
        // Extract compression algorithms.
        set<MslConstants::CompressionAlgorithm> compressionAlgos;
        shared_ptr<MslArray> algos = capabilitiesMo->optMslArray(KEY_COMPRESSION_ALGOS);
        if (algos) {
            for (size_t i = 0; i < algos->size(); ++i) {
                const string algo = algos->getString((int)i);
                // Ignore unsupported algorithms.
                try {
                    compressionAlgos.insert(MslConstants::CompressionAlgorithm::fromString(algo));
                } catch (const IllegalArgumentException& e) {}
            }
        }
        compressionAlgos_ = compressionAlgos;

        // Extract languages.
        vector<string> languages;
        shared_ptr<MslArray> langs = capabilitiesMo->optMslArray(KEY_LANGUAGES);
        if (langs) {
            for (size_t i = 0; i < langs->size(); ++i)
                languages.push_back(langs->getString((int)i));
        }
        languages_ = languages;

        // Extract encoder formats.
        set<MslEncoderFormat> encoderFormats;
        shared_ptr<MslArray> formats = capabilitiesMo->optMslArray(KEY_ENCODER_FORMATS);
        if (formats) {
            for (size_t i = 0; i < formats->size(); ++i) {
                const string format = formats->getString((int)i);
                const MslEncoderFormat encoderFormat = MslEncoderFormat::getFormat(format);
                // Ignore unsupported formats.
                if (encoderFormat != MslEncoderFormat::INVALID)
                    encoderFormats.insert(encoderFormat);
            }
        }
        encoderFormats_ = encoderFormats;
    } catch (const MslEncoderException& e) {
        stringstream ss;
        ss << "capabilities " << capabilitiesMo;
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, ss.str(), e);
    }
}

shared_ptr<ByteArray> MessageCapabilities::toMslEncoding(shared_ptr<MslEncoderFactory> encoder,
        const MslEncoderFormat& format) const
{
    try {
        shared_ptr<MslObject> mo = encoder->createObject();

        // compression algos
        shared_ptr<MslArray> algos = encoder->createArray();
        std::set<MslConstants::CompressionAlgorithm>::const_iterator it;
        int i = 0;
        for (it = compressionAlgos_.begin(), i = 0; it != compressionAlgos_.end(); ++it, ++i)
            algos->put<string>(i, it->toString());
        mo->put(KEY_COMPRESSION_ALGOS, algos);

        // languages
        shared_ptr<MslArray> languages = encoder->createArray();
        vector<string>::const_iterator jt;
        i = 0;
        for (jt = languages_.begin(), i = 0; jt != languages_.end(); ++jt, ++i)
            languages->put<string>(i, *jt);
        mo->put(KEY_LANGUAGES, languages);

        // encoder formats
        shared_ptr<MslArray> formats = encoder->createArray();
        set<MslEncoderFormat>::const_iterator kt;
        i = 0;
        for (kt = encoderFormats_.begin(), i = 0; kt != encoderFormats_.end(); ++kt, ++i)
            formats->put<string>(i, kt->toString());
        mo->put(KEY_ENCODER_FORMATS, formats);

        return encoder->encodeObject(mo, format);
    } catch (const MslEncoderException& e) {
        throw MslInternalException("Error encoding MessageCapabilities.", e);
    }
}

bool MessageCapabilities::equals(shared_ptr<const MessageCapabilities> that) const
{
    if (!that) return false;
    if (this == that.get()) return true;
    return (compressionAlgos_ == that->compressionAlgos_) &&
           (encoderFormats_ == that->encoderFormats_) &&
           (languages_ == that->languages_);
}

bool operator==(const MessageCapabilities& a, const MessageCapabilities& b)
{
	shared_ptr<const MessageCapabilities> ap(&a, &MslUtils::nullDeleter<MessageCapabilities>);
	shared_ptr<const MessageCapabilities> bp(&b, &MslUtils::nullDeleter<MessageCapabilities>);
	return ap->equals(bp);
}

}}} // namespace netflix::msl::msg

