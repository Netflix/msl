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

#ifndef SRC_IO_MSLENCODERUTILS_H_
#define SRC_IO_MSLENCODERUTILS_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <io/MslEncoderFormat.h>

namespace netflix {
namespace msl {

typedef std::vector<uint8_t> ByteArray;

namespace util { class MslContext; }
namespace io {

class MslArray; class MslObject; class Variant;

namespace MslEncoderUtils
{
	/**
	 * URL-safe Base64 encode data as UTF-8 without padding characters.
	 *
	 * @param s the value to Base64 encode.
	 * @return the Base64 encoded data.
	 */
	std::shared_ptr<std::string> b64urlEncode(std::shared_ptr<std::string> s);

	/**
	 * URL-safe Base64 encode data without padding characters.
	 *
	 * @param data the value to Base64 encode.
	 * @return the Base64 encoded data.
	 */
	std::shared_ptr<std::string> b64urlEncode(std::shared_ptr<ByteArray> data);

	/**
	 * URL-safe Base64 decode data that has no padding characters.
	 *
	 * @param data the Base64 encoded data.
	 * @return the decoded data.
	 * @throws IllegalArgumentException if there is an error decoding.
	 */
	std::shared_ptr<ByteArray> b64urlDecode(std::shared_ptr<std::string> data);

	/**
	 * Create a MSL array from a collection of objects that are either one of
	 * the accepted types: <code>Boolean</code>, <code>Byte[]</code>,
	 * <code>MslArray</code>, <code>MslObject</code>, <code>Number</code>,
	 * <code>String</code>, <code>null</code>, or turn any
	 * <code>MslEncodable</code> into a <code>MslObject</code>.
	 *
	 * @param ctx MSL context.
	 * @param format MSL encoder format.
	 * @param c a collection of MSL encoding-compatible objects.
	 * @return the constructed MSL array.
	 * @throws MslEncoderException if a <code>MslEncodable</code> cannot be
	 *         encoded properly or an unsupported object is encountered.
	 */
	std::shared_ptr<MslArray> createArray(std::shared_ptr<util::MslContext> ctx, const MslEncoderFormat& format, const std::vector<Variant>& c);

	/**
	 * Performs a deep comparison of two MSL objects for equivalence. MSL
	 * objects are equivalent if they have the same name/value pairs. Also, two
	 * MSL object references are considered equal if both are null.
	 *
	 * @param mo1 first MSL object. May be null.
	 * @param mo2 second MSL object. May be null.
	 * @return true if the MSL objects are equivalent.
	 * @throws MslEncoderException if there is an error parsing the data.
	 */
	bool equalObjects(std::shared_ptr<MslObject> mo1, std::shared_ptr<MslObject> mo2);

	/**
	 * Performs a deep comparison of two MSL arrays for equality. Two MSL
	 * arrays are considered equal if both arrays contain the same number of
	 * elements, and all corresponding pairs of elements in the two arrays are
	 * equal. In other words, two MSL arrays are equal if they contain the
	 * same elements in the same order. Also, two MSL array references are
	 * considered equal if both are null.
	 *
	 * @param ma1 first MSL array. May be null.
	 * @param ma2 second MSL array. May be null.
	 * @return true if the MSL arrays are equal.
	 * @throws MslEncoderException if there is an error parsing the data.
	 */
	bool equalArrays(std::shared_ptr<MslArray> ma1, std::shared_ptr<MslArray> ma2);

    /**
     * Performs a shallow comparison of two MSL arrays for set equality. Two
     * MSL arrays are considered set-equal if both arrays contain the same
     * number of elements and all elements found in one array are also found in
     * the other. In other words, two MSL arrays are set-equal if they contain
     * the same elements in the any order. Also, two MSL array references are
     * considered set-equal if both are null.
     *
     * @param ma1 first MSL array. May be {@code null}.
     * @param ma2 second MSL array. May be {@code null}.
     * @return true if the MSL arrays are set-equal.
     * @throws MslEncoderException if there is an error parsing the data.
     */
	// FIXME
	//static bool equalSets(std::shared_ptr<MslArray> ma1, std::shared_ptr<MslArray> ma2);

    /**
     * Merge two MSL objects into a single MSL object. If the same key is
     * found in both objects, the second object's value is used. The values are
     * copied by reference so this is a shallow copy.
     *
     * @param mo1 first MSL object. May be null.
     * @param mo2 second MSL object. May be null.
     * @return the merged MSL object or null if both arguments are null.
     * @throws MslEncoderException if a value in one of the arguments is
     *         invalid—this should not happen.
     */
	std::shared_ptr<MslObject> merge(std::shared_ptr<MslObject> mo1, std::shared_ptr<MslObject> mo2);
}

}}} // namespace netflix::msl::io

#endif
