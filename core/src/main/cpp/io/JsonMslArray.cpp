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

#include <io/JsonMslArray.h>
#include <io/JsonHandler.h>
#include <io/JsonVisitor.h>
#include <io/JsonMslObject.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/StringVisitor.h>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/reader.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <util/Base64.h>
#include <sstream>

using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace io {

using namespace std;
using namespace rapidjson;

JsonMslArray::JsonMslArray()
{}

JsonMslArray::JsonMslArray(shared_ptr<MslArray> a)
{
	try {
		for (int i = 0; i < static_cast<int>(a->size()); ++i)
			put(i, a->opt(i));
	} catch (const IllegalArgumentException& e) {
		throw MslEncoderException("Invalid MSL array encoding.", e);
	}
}

JsonMslArray::JsonMslArray(shared_ptr<ByteArray> encoding)
{
    // FIXME: rapidjson config: encoding, memory pool, stop parsing at 1st obj, etc

    // Parse the incoming encoding into a DOM object. JSON syntax checking is
    // done here by rapidjson.
    Document document;
    try {
        // Insert a trailing null character so rapidjson can parse the data as a
        // null-terminated string. Make sure to remove it before returning so
    	// the caller does not see any change in size.
        class AddTempNull
        {
        public:
            AddTempNull(shared_ptr<ByteArray>& ba) : ba(ba) { ba->push_back(0); }
            ~AddTempNull() { ba->pop_back(); }
        private:
            shared_ptr<ByteArray>& ba;
        };
        AddTempNull addTempNull(encoding);
    	if (document.Parse(reinterpret_cast<const char*>(&(*encoding)[0])).HasParseError()) {
            ParseErrorCode e = document.GetParseError();
            size_t o = document.GetErrorOffset();
            stringstream ss;
            ss << "Invalid JSON encoding: " << GetParseError_En(e);
            ss << " at offset " << o << "...'";
            throw MslEncoderException(ss.str());
        }
    }
    catch (...) {
        throw MslEncoderException("Invalid JSON encoding");
    }

    // Assume we now have a well-formed DOM. Translate to a MslObject.
    shared_ptr<MslArray> newArray = make_shared<JsonMslArray>();
    JsonHandler handler(newArray);
    try {
        document.Accept(handler);
    }
    catch (const Exception& e) {
        throw MslEncoderException("Error when building JsonMslObject", e);
    }

    // If all went well, commit the data to this
	try {
		for (int i = 0; i < static_cast<int>(newArray->size()); ++i)
			put(-1, newArray->opt(i));
	} catch (const IllegalArgumentException& e) {
		throw MslEncoderException("Invalid MSL object encoding.", e);
	}
}

void JsonMslArray::put(int index, const Variant& value)
{
	Variant o = value;
	try {
		// Convert MslObject to JsonMslObject.
		if (value.isType<shared_ptr<MslObject>>() && !value.isType<shared_ptr<JsonMslObject>>())
			o = VariantFactory::create<shared_ptr<MslObject>>(make_shared<JsonMslObject>(value.get<shared_ptr<MslObject>>()));
		// Convert MslArray to JsonMslArray.
		else if (value.isType<shared_ptr<MslArray>>() && !value.isType<shared_ptr<JsonMslArray>>())
			o = VariantFactory::create<shared_ptr<MslArray>>(make_shared<JsonMslArray>(value.get<shared_ptr<MslArray>>()));
		// All other types are OK as-is.
	} catch (const MslEncoderException& e) {
		throw IllegalArgumentException("Unsupported JSON object or array representation.", e);
	}
	MslArray::put(index, o);
}

shared_ptr<ByteArray> JsonMslArray::getBytes(int index) const
{
    // When a JsonMslArray is decoded, there's no way for us to know if a
    // value is supposed to be a String or a ByteArray. Therefore interpret
    // Strings as Base64-encoded data consistent with the toJSONString()
    // and getEncoded().
    const Variant value = get(index);
    if (value.isType<shared_ptr<ByteArray>>()) {
        return value.get<shared_ptr<ByteArray>>();
    } else if (value.isType<string>()) {
        const string strVal = value.get<string>();
        try {
        	return util::Base64::decode(strVal);
        } catch (const IllegalArgumentException& e) {
            throw MslEncoderException("found non-b64 data when auto-converting string to ByteArray", e);
        }
    } else {
        stringstream s;
        s << "JsonMslArray[" << index << "] is not binary data.";
        throw MslEncoderException(s.str());
    }
}

// The rapidjson parser places parsed numbers into their smallest necessary
// type. This means we must up-cast if the expected type is actually larger.
int64_t JsonMslArray::getLong(int index) const
{
    const Variant variant = get(index);
    if (variant.isType<int32_t>())
    	return static_cast<int64_t>(variant.get<int32_t>());
    else if (variant.isType<int64_t>())
    	return variant.get<int64_t>();
    else if (variant.isType<double>())
    	return static_cast<int64_t>(variant.get<double>());
    stringstream ss;
    ss << "MslArray[" << index << "] is not a number.";
    throw MslEncoderException(ss.str());
}

double JsonMslArray::getDouble(int index) const
{
	const Variant variant = get(index);
	if (variant.isType<int32_t>())
		return static_cast<double>(variant.get<int32_t>());
	else if (variant.isType<int64_t>())
		return static_cast<double>(variant.get<int64_t>());
	else if (variant.isType<double>())
		return variant.get<double>();
    stringstream ss;
    ss << "MslArray[" << index << "] is not a number.";
    throw MslEncoderException(ss.str());
}

shared_ptr<ByteArray> JsonMslArray::optBytes(int index, shared_ptr<ByteArray> defaultValue) const
{
    // When a JsonMslArray is decoded, there's no way for us to know if a
    // value is supposed to be a String or a ByteArray. Therefore interpret
    // Strings as Base64-encoded data consistent with the toJSONString()
    // and getEncoded().
    const Variant value = opt(index);
    if (value.isType<shared_ptr<ByteArray>>()) {
        return value.get<shared_ptr<ByteArray>>();
    } else if (value.isType<string>()) {
        const string strVal = value.get<string>();
        try {
        	return util::Base64::decode(strVal);
        } catch (const IllegalArgumentException& e) {
            throw MslEncoderException("found non-b64 data when auto-converting string to ByteArray", e);
        }
    } else {
    	return defaultValue;
    }
}

// The rapidjson parser places parsed numbers into their smallest necessary
// type. This means we must up-cast if the expected type is actually larger.
int64_t JsonMslArray::optLong(int index, int64_t defaultValue) const
{
    const Variant variant = opt(index);
    if (variant.isType<int32_t>())
    	return static_cast<int64_t>(variant.get<int32_t>());
    else if (variant.isType<int64_t>())
    	return variant.get<int64_t>();
    else if (variant.isType<double>())
    	return static_cast<int64_t>(variant.get<double>());
    else
    	return defaultValue;
}

double JsonMslArray::optDouble(int index, double defaultValue) const
{
	const Variant variant = opt(index);
	if (variant.isType<int32_t>())
		return static_cast<double>(variant.get<int32_t>());
	else if (variant.isType<int64_t>())
		return static_cast<double>(variant.get<int64_t>());
	else if (variant.isType<double>())
		return variant.get<double>();
	else
		return defaultValue;
}

string JsonMslArray::toJsonString(shared_ptr<MslEncoderFactory> encoder) const
{
    StringBuffer s;
    Writer<StringBuffer> writer(s);
    JsonVisitor visitor(encoder, writer);
    shared_ptr<MslArray> ma = make_shared<MslArray>(getCollection()); // copy
    visitor.visit(ma);
    return s.GetString();
}

string JsonMslArray::toString() const
{
    StringVisitor visitor;
    shared_ptr<MslArray> ma = make_shared<MslArray>(getCollection()); // copy
    visitor.visit(ma);
    return visitor.getString();
}

}}} // namesapce netflix::msl::io
