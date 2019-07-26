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

#include <io/MslEncoderUtils.h>
#include <Enum.h>
#include <io/MslArray.h>
#include <io/MslEncoderFactory.h>
#include <io/MslObject.h>
#include <io/MslVariant.h>
#include <util/Base64.h>
#include <util/MslContext.h>

using namespace std;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace io {
namespace MslEncoderUtils {

namespace {
/** Base64 characters. */
const char CHAR_PLUS = '+';
const char CHAR_MINUS = '-';
const char CHAR_SLASH = '/';
const char CHAR_UNDERSCORE = '_';
const char CHAR_EQUALS = '=';
} // namespace anonymous

shared_ptr<string> b64urlEncode(shared_ptr<string> s) {
	shared_ptr<ByteArray> data = make_shared<ByteArray>(s->begin(), s->end());
	return b64urlEncode(data);

}

shared_ptr<string> b64urlEncode(shared_ptr<ByteArray> data) {
	// Perform a standard Base64 encode.
	shared_ptr<string> modified = Base64::encode(data);

	// Replace standard characters with URL-safe characters.
	replace(modified->begin(), modified->end(), CHAR_PLUS, CHAR_MINUS);
	replace(modified->begin(), modified->end(), CHAR_SLASH, CHAR_UNDERSCORE);

	// Remove padding.
	const size_t padIndex = modified->find(CHAR_EQUALS);
	return (padIndex != string::npos) ? make_shared<string>(modified->substr(0, padIndex)) : modified;
}

shared_ptr<ByteArray> b64urlDecode(shared_ptr<string> data) {
	// Replace URL-safe characters with standard characters.
	shared_ptr<string> modified = make_shared<string>();
	*modified = *data;
	replace(modified->begin(), modified->end(), CHAR_MINUS, CHAR_PLUS);
	replace(modified->begin(), modified->end(), CHAR_UNDERSCORE, CHAR_SLASH);

	// Pad if necessary, then decode.
	const size_t toPad = 4 - (modified->length() % 4);
	if (toPad == 0 || toPad == 4)
		return Base64::decode(modified);
	for (int i = 0; i < (int)toPad; ++i)
		modified->push_back(CHAR_EQUALS);
	return Base64::decode(modified);
}

shared_ptr<MslArray> createArray(shared_ptr<MslContext> ctx, const MslEncoderFormat& format, const vector<Variant>& c) {
	shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
	shared_ptr<MslArray> array = encoder->createArray();
	for (vector<Variant>::const_iterator o = c.begin();
		 o != c.end();
		 ++o)
	{
		// FIXME: This can go away once we have compile-time static type
		// checks.
		//
		// FIXME: If the encoder doesn't know how to accept a type, it
		// should fail at compile time if the encoder does not have
		// dynamic typing. And if the encoder author doesn't just add types
		// that shouldn't be supported.
		if (o->isType<shared_ptr<ByteArray>>() ||
			o->isType<bool>() ||
			o->isType<shared_ptr<MslArray>>() ||
			o->isType<shared_ptr<MslObject>>() ||
			o->isType<int>() ||
			o->isType<long>() ||
			o->isType<float>() ||
			o->isType<double>() ||
			o->isType<string>() ||
			o->isType<map<string,Variant>>() ||
			o->isType<vector<Variant>>() ||
			o->isType<Variant[]>() ||
			o->isNull())
		{
			array->put(-1, *o);
		} else if (o->isType<shared_ptr<MslEncodable>>()) {
			const shared_ptr<MslEncodable> me = o->get<shared_ptr<MslEncodable>>();
			shared_ptr<ByteArray> encode = me->toMslEncoding(encoder, format);
			shared_ptr<MslObject> mo = encoder->parseObject(encode);
			array->put(-1, mo);
		} else {
			// FIXME: This should list the variant value type.
			stringstream ss;
			ss << "Class " << "<variant>" << " is not MSL encoding-compatible.";
			throw MslEncoderException(ss.str());
		}
	}
	return array;
}

bool equalObjects(shared_ptr<MslObject> mo1, shared_ptr<MslObject> mo2) {
	// Equal if both null or the same object.
	if (mo1 == mo2)
		return true;
	// Not equal if only one of them is null.
	if (!mo1 || !mo2)
		return false;

	// Check the children names. If there are no names, the MSL object is
	// empty.
	const vector<string> names1 = mo1->getKeys();
	const vector<string> names2 = mo2->getKeys();
	// Not equal if only one of them is null or of different length.
	if (names1.size() != names2.size())
		return false;
	// Not equal if the sets are not equal.
	if (names1 != names2)
		return false;

	// Bail on the first child element whose values are not equal.
	for (vector<string>::const_iterator it = names1.begin();
		 it != names1.end();
		 ++it)
	{
		const string& name = *it;
		Variant o1 = mo1->opt(name);
		Variant o2 = mo2->opt(name);
		// Equal if both null or the same object.
		if (o1 == o2) continue;
		// Not equal if only one of them is null.
		if (o1.isNull() || o2.isNull())
			return false;
		// byte[] may be represented differently, so we have to compare by
		// accessing directly. This isn't perfect but works for now.
		if (o1.isType<shared_ptr<ByteArray>>() || o2.isType<shared_ptr<ByteArray>>()) {
			shared_ptr<ByteArray> b1 = mo1->getBytes(name);
			shared_ptr<ByteArray> b2 = mo2->getBytes(name);
			if (*b1 != *b2)
				return false;
		} else if (o1.isType<shared_ptr<MslObject>>() && o2.isType<shared_ptr<MslObject>>()) {
			if (!equalObjects(o1.get<shared_ptr<MslObject>>(), o2.get<shared_ptr<MslObject>>()))
				return false;
		} else if (o1.isType<shared_ptr<MslArray>>() && o2.isType<shared_ptr<MslArray>>()) {
			if (!equalArrays(o1.get<shared_ptr<MslArray>>(), o2.get<shared_ptr<MslArray>>()))
				return false;
		} else {
			if (o1 != o2)
				return false;
		}
	}

	// All name/value pairs are equal.
	return true;
}

bool equalArrays(shared_ptr<MslArray> ma1, shared_ptr<MslArray> ma2) {
	// Equal if both null or the same object.
	if (ma1 == ma2)
		return true;
	// Not equal if only one of them is null or of different length.
	if (!ma1 || !ma2 || ma1->size() != ma2->size())
		return false;

	// Bail on the first elements whose values are not equal.
	for (int i = 0; i < (int)ma1->size(); ++i) {
		Variant o1 = ma1->opt(i);
		Variant o2 = ma2->opt(i);
		// Equal if both null or the same object.
		if (o1 == o2) continue;
		// Not equal if only one of them is null.
		if (o1.isNull() || o2.isNull())
			return false;
		// byte[] may be represented differently, so we have to compare by
		// accessing directly. This isn't perfect but works for now.
		if (o1.isType<shared_ptr<ByteArray>>() || o2.isType<shared_ptr<ByteArray>>()) {
			shared_ptr<ByteArray> b1 = ma1->getBytes(i);
			shared_ptr<ByteArray> b2 = ma2->getBytes(i);
			if (*b1 != *b2)
				return false;
		} else if (o1.isType<shared_ptr<MslObject>>() && o2.isType<shared_ptr<MslObject>>()) {
			if (!equalObjects(o1.get<shared_ptr<MslObject>>(), o2.get<shared_ptr<MslObject>>()))
				return false;
		} else if (o1.isType<shared_ptr<MslArray>>() && o2.isType<shared_ptr<MslArray>>()) {
			if (!equalArrays(o1.get<shared_ptr<MslArray>>(), o2.get<shared_ptr<MslArray>>()))
				return false;
		} else {
			if (o1 != o2)
				return false;
		}
	}

	// All values are equal.
	return true;
}

/* FIXME
bool equalSets(shared_ptr<MslArray> ma1, shared_ptr<MslArray> ma2) {
    // Equal if both null or the same object.
    if (ma1 == ma2)
        return true;
    // Not equal if only one of them is null or of different length.
    if (!ma1 || !ma2 || ma1->size() != ma2->size())
        return false;

    // Compare as sets.
    set<Variant> s1;
    set<Variant> s2;
    for (int i = 0; i < (int)ma1->size(); ++i) {
    	// FIXME: This requires Variant::operator<
        s1.insert(ma1->opt(i));
        s2.insert(ma2->opt(i));
    }
    return s1 == s2;
}
*/

shared_ptr<MslObject> merge(shared_ptr<MslObject> mo1, shared_ptr<MslObject> mo2) {
    // Return null if both objects are null.
    if (!mo1 && !mo2)
        return shared_ptr<MslObject>();

    // Make a copy of the first object, or create an empty object.
    shared_ptr<MslObject> mo = (mo1)
    	? make_shared<MslObject>(mo1->getMap())
    	: make_shared<MslObject>();

    // If the second object is null, we're done and just return the copy.
    if (!mo2)
        return mo;

    // Copy the contents of the second object into the final object.
    vector<string> keys = mo2->getKeys();
    for (vector<string>::iterator key = keys.begin();
    	 key != keys.end();
    	 ++key)
    {
    	mo->put(*key, mo2->get(*key));
    }
    return mo;
}

}}}} // namespace netflix::msl::io::MslEncoderUtils
