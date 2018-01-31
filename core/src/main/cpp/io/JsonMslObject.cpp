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

#include <io/JsonMslObject.h>
#include <Macros.h>
#include <io/JsonHandler.h>
#include <io/JsonMslArray.h>
#include <io/JsonVisitor.h>
#include <io/MslEncoderFactory.h>
#include <io/MslObject.h>
#include <io/StringVisitor.h>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <util/Base64.h>
#include <memory>
#include <sstream>
#include <string>

using namespace std;
using namespace rapidjson;

namespace netflix {
namespace msl {
namespace io {

JsonMslObject::JsonMslObject()
{}

JsonMslObject::JsonMslObject(shared_ptr<MslObject> o)
{
	try {
		const vector<string> keys = o->getKeys();
		for (vector<string>::const_iterator key = keys.begin();
			 key != keys.end();
			 ++key)
		{
			const Variant v = o->opt(*key);
			put(*key, v);
		}
	} catch (const IllegalArgumentException& e) {
		throw MslEncoderException("Invalid MSL object encoding.", e);
	}
}

JsonMslObject::JsonMslObject(shared_ptr<ByteArray> encoding)
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
            const ParseErrorCode e = document.GetParseError();
            const size_t o = document.GetErrorOffset();
            stringstream ss;
            ss << "Invalid JSON encoding: " << GetParseError_En(e);
            ss << " (at offset " << o << "...')";
            throw MslEncoderException(ss.str());
        }
    } catch (const MslEncoderException& e) {
        throw e;
    } catch (...) {
        throw MslEncoderException("Invalid JSON encoding");
    }

    // Assume we now have a well-formed DOM. Translate to a MslObject.
    shared_ptr<MslObject> newObj = make_shared<JsonMslObject>();
    JsonHandler handler(newObj);
    try {
        document.Accept(handler);
    } catch (const Exception& e) {
        throw MslEncoderException("Error when building JsonMslObject", e);
    }

    // If all went well, commit the data to this
	try {
		const vector<string> keys = newObj->getKeys();
		for (vector<string>::const_iterator key = keys.begin();
			 key != keys.end();
			 ++key)
		{
			const Variant v = newObj->opt(*key);
			put(*key, v);
		}
	} catch (const IllegalArgumentException& e) {
		throw MslEncoderException("Invalid MSL object encoding.", e);
	}
}

void JsonMslObject::put(const std::string& key, const Variant& value)
{
	Variant o = value;
	try {
		// Convert MslObject to JsonMslObject. Leave JsonMslObject as-is.
		if (value.isType<shared_ptr<MslObject>>()) {
			shared_ptr<MslObject> mo = value.get<shared_ptr<MslObject>>();
			shared_ptr<JsonMslObject> jmo = dynamic_pointer_cast<JsonMslObject>(mo);
			if (!jmo)
				o = VariantFactory::create<shared_ptr<MslObject>>(make_shared<JsonMslObject>(mo));
		}
		// Convert MslArray to JsonMslArray. Leave JsonMslArray as-is.
		else if (value.isType<shared_ptr<MslArray>>() && !value.isType<shared_ptr<JsonMslArray>>()) {
			shared_ptr<MslArray> ma = value.get<shared_ptr<MslArray>>();
			shared_ptr<JsonMslArray> jma = dynamic_pointer_cast<JsonMslArray>(ma);
			if (!jma)
				o = VariantFactory::create<shared_ptr<MslArray>>(make_shared<JsonMslArray>(ma));
		}
		// All other types are OK as-is.
	} catch (const MslEncoderException& e) {
		throw IllegalArgumentException("Unsupported JSON object or array representation.", e);
	}
	MslObject::put(key, o);
}

shared_ptr<ByteArray> JsonMslObject::getBytes(const std::string& key) const
{
    // When a JsonMslObject is decoded, there's no way for us to know if a
    // value is supposed to be a String or a ByteArray. Therefore interpret
    // Strings as Base64-encoded data consistent with the toJSONString()
    // and getEncoded().
    const Variant value = get(key);
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
        s << "JsonMslObject[" << key << "] is not binary data.";
        throw MslEncoderException(s.str());
    }
}

// The rapidjson parser places parsed numbers into their smallest necessary
// type. This means we must up-cast if the expected type is actually larger.
int64_t JsonMslObject::getLong(const string& key) const
{
    const Variant variant = get(key);
    if (variant.isType<int32_t>())
    	return static_cast<int64_t>(variant.get<int32_t>());
    else if (variant.isType<int64_t>())
    	return variant.get<int64_t>();
    else if (variant.isType<double>())
    	return static_cast<int64_t>(variant.get<double>());
    stringstream ss;
    ss << "MslObject[" << MslEncoderFactory::quote(key) << "] is not a number.";
    throw MslEncoderException(ss.str());
}

double JsonMslObject::getDouble(const string& key) const
{
	const Variant variant = get(key);
	if (variant.isType<int32_t>())
		return static_cast<double>(variant.get<int32_t>());
	else if (variant.isType<int64_t>())
		return static_cast<double>(variant.get<int64_t>());
	else if (variant.isType<double>())
		return variant.get<double>();
	stringstream ss;
	ss << "MslObject[" << MslEncoderFactory::quote(key) << "] is not a number.";
	throw MslEncoderException(ss.str());
}

shared_ptr<ByteArray> JsonMslObject::optBytes(const std::string& key, shared_ptr<ByteArray> defaultValue) const
{
    // When a JsonMslObject is decoded, there's no way for us to know if a
    // value is supposed to be a String or a ByteArray. Therefore interpret
    // Strings as Base64-encoded data consistent with the toJSONString()
    // and getEncoded().
    const Variant value = opt(key);
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
int64_t JsonMslObject::optLong(const string& key, int64_t defaultValue) const
{
    const Variant variant = opt(key);
    if (variant.isType<int32_t>())
    	return static_cast<int64_t>(variant.get<int32_t>());
    else if (variant.isType<int64_t>())
    	return variant.get<int64_t>();
    else if (variant.isType<double>())
    	return static_cast<int64_t>(variant.get<double>());
    else
    	return defaultValue;
}

double JsonMslObject::optDouble(const string& key, double defaultValue) const
{
	const Variant variant = opt(key);
	if (variant.isType<int32_t>())
		return static_cast<double>(variant.get<int32_t>());
	else if (variant.isType<int64_t>())
		return static_cast<double>(variant.get<int64_t>());
	else if (variant.isType<double>())
		return variant.get<double>();
	else
		return defaultValue;
}

std::string JsonMslObject::toJsonString(shared_ptr<MslEncoderFactory> encoder) const
{
	// FIXME
    StringBuffer s;
    Writer<StringBuffer> writer(s);
    JsonVisitor visitor(encoder, writer);
    shared_ptr<MslObject> mo = make_shared<MslObject>(getMap()); // copy
    visitor.visit(mo);
    return s.GetString();
}

std::string JsonMslObject::toString() const
{
    StringVisitor visitor;
    shared_ptr<MslObject> mo = make_shared<MslObject>(getMap()); // copy
    visitor.visit(mo);
    return visitor.getString();
}

//static
shared_ptr<ByteArray> JsonMslObject::getEncoded(shared_ptr<MslEncoderFactory> encoder, shared_ptr<MslObject> object)
{
    std::string json;
    const MslObject& mo = *object;
    if (typeid(mo) == typeid(JsonMslObject)) {
        shared_ptr<JsonMslObject> jmo = dynamic_pointer_cast<JsonMslObject>(object);
        json = jmo->toJsonString(encoder);
    } else {
        shared_ptr<JsonMslObject> jmo = make_shared<JsonMslObject>(object);
        json = jmo->toJsonString(encoder);
    }
    return make_shared<ByteArray>(json.begin(), json.end());
}


}}} // namespace netflix::msl::io

