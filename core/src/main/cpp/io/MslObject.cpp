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

#include <io/MslArray.h>
#include <io/MslEncoderFactory.h>
#include <io/MslObject.h>
#include <sstream>
#include <util/Base64.h>

using namespace std;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace io {

MslObject::MslObject(const MapType& map) : map_(make_shared<MapType>())
{
    // FIXME: Should we iterate over the map and ensure that no disallowed types are present?
    MapType newMap = map;
    map_->swap(newMap);
}

void MslObject::put(const string& key, const Variant& value)
{
    if (key.empty())
        throw IllegalArgumentException("empty key");
    MapType newMap(*map_); // operate on a copy
    newMap.erase(key); // does nothing if key not present
    // stop with the remove if requested
    if (value.isNull()) {
        map_->swap(newMap);
        return;
    }
    newMap.insert(make_pair(key, value));
    map_->swap(newMap); // commit the result
}

template<>
void MslObject::put<shared_ptr<MslObject>>(const string& key, const shared_ptr<MslObject>& value)
{
	STATIC_ASSERT(isAllowed<shared_ptr<MslObject>>::value);
	// Empty shared pointers are equivalent to NULL.
	if (!value) put(key, VariantFactory::createNull());
	else put(key, VariantFactory::create<shared_ptr<MslObject>>(value));
}

template<>
void MslObject::put<shared_ptr<MslArray>>(const string& key, const shared_ptr<MslArray>& value)
{
	STATIC_ASSERT(isAllowed<shared_ptr<MslArray>>::value);
	// Empty shared pointers are equivalent to NULL.
	if (!value) put(key, VariantFactory::createNull());
	else put(key, VariantFactory::create<shared_ptr<MslArray>>(value));
}

template<>
void MslObject::put<shared_ptr<MslEncodable>>(const string& key, const shared_ptr<MslEncodable>& value)
{
	STATIC_ASSERT(isAllowed<shared_ptr<MslEncodable>>::value);
	// Empty shared pointers are equivalent to NULL.
	if (!value) put(key, VariantFactory::createNull());
	else put(key, VariantFactory::create<shared_ptr<MslEncodable>>(value));
}

Variant MslObject::get(const string& key) const
{
    if (key.empty())
        throw IllegalArgumentException("empty key");
    MapType::const_iterator it = map_->find(key);
    if (it == map_->end()) {
    	stringstream ss;
    	ss << "MslObject[" + MslEncoderFactory::quote(key) + "] not found.";
    	throw MslEncoderException(ss.str());
    }
    const Variant& value = it->second;
    if (value.isNull()) {
    	stringstream ss;
    	ss << "MslObject[" + MslEncoderFactory::quote(key) + "] not found.";
    	throw MslEncoderException(ss.str());
    }
    return value;
}

bool MslObject::getBoolean(const string& key) const
{
	Variant variant = get(key);
	if (variant.isType<bool>())
		return variant.get<bool>();
	stringstream ss;
	ss << "MslObject[" + MslEncoderFactory::quote(key) + "] is not a boolean.";
	throw MslEncoderException(ss.str());
}

shared_ptr<ByteArray> MslObject::getBytes(const string& key) const
{
	Variant variant = get(key);
	if (variant.isType<shared_ptr<ByteArray>>())
		return variant.get<shared_ptr<ByteArray>>();
	stringstream ss;
	ss << "MslObject[" + MslEncoderFactory::quote(key) + "] is not binary data.";
	throw MslEncoderException(ss.str());
}

double MslObject::getDouble(const string& key) const
{
	Variant variant = get(key);
	if (variant.isType<int32_t>())
		return static_cast<double>(variant.get<int32_t>());
	if (variant.isType<int64_t>())
		return static_cast<double>(variant.get<int64_t>());
	if (variant.isType<double>())
		return variant.get<double>();
	stringstream ss;
	ss << "MslObject[" + MslEncoderFactory::quote(key) + "] is not a number.";
	throw MslEncoderException(ss.str());
}

int32_t MslObject::getInt(const string& key) const
{
	Variant variant = get(key);
	if (variant.isType<int32_t>())
		return variant.get<int32_t>();
	if (variant.isType<int64_t>())
		return static_cast<int32_t>(variant.get<int64_t>());
	if (variant.isType<double>())
		return static_cast<int32_t>(variant.get<double>());
	stringstream ss;
	ss << "MslObject[" + MslEncoderFactory::quote(key) + "] is not a number.";
	throw MslEncoderException(ss.str());
}

shared_ptr<MslArray> MslObject::getMslArray(const string& key) const
{
	Variant variant = get(key);
	if (variant.isType<shared_ptr<MslArray>>())
		return variant.get<shared_ptr<MslArray>>();
	stringstream ss;
	ss << "MslObject[" + MslEncoderFactory::quote(key) + "] is not a MslArray.";
	throw MslEncoderException(ss.str());
}

shared_ptr<MslObject> MslObject::getMslObject(const string& key, std::shared_ptr<MslEncoderFactory> encoder) const
{
    Variant variant = get(key);
    if (variant.isType<shared_ptr<MslObject>>())
        return variant.get<shared_ptr<MslObject>>();
    if (variant.isType<shared_ptr<ByteArray>>()) {
    	try {
    		return encoder->parseObject(variant.get<shared_ptr<ByteArray>>());
    	} catch (const MslEncoderException& e) {
    	    stringstream ss;
    	    ss << "MslObject[" + MslEncoderFactory::quote(key) + "] is not a MslObject.";
    	    throw MslEncoderException(ss.str());
    	}
    }
    stringstream ss;
    ss << "MslObject[" + MslEncoderFactory::quote(key) + "] is not a MslObject.";
    throw MslEncoderException(ss.str());
}

int64_t MslObject::getLong(const string& key) const
{
	Variant variant = get(key);
	if (variant.isType<int32_t>())
		return static_cast<int64_t>(variant.get<int32_t>());
	if (variant.isType<int64_t>())
		return variant.get<int64_t>();
	if (variant.isType<double>())
		return static_cast<int64_t>(variant.get<double>());
	stringstream ss;
	ss << "MslObject[" + MslEncoderFactory::quote(key) + "] is not a number.";
	throw MslEncoderException(ss.str());
}

string MslObject::getString(const string& key) const
{
	Variant variant = get(key);
	if (variant.isType<string>())
		return variant.get<string>();
	stringstream ss;
	ss << "MslObject[" + MslEncoderFactory::quote(key) + "] is not a string.";
	throw MslEncoderException(ss.str());
}

Variant MslObject::opt(const string& key) const
{
    if (key.empty())
        throw IllegalArgumentException("empty key");
    try {
        return get(key);
    } catch (const MslEncoderException& e) {
        return VariantFactory::createNull();
    }
}

bool MslObject::optBoolean(const string& key, bool defaultValue) const
{
	Variant variant = opt(key);
	if (variant.isType<bool>())
		return variant.get<bool>();
	return defaultValue;
}

shared_ptr<ByteArray> MslObject::optBytes(const string& key, shared_ptr<ByteArray> defaultValue) const
{
	Variant variant = opt(key);
	if (variant.isType<shared_ptr<ByteArray>>())
		return variant.get<shared_ptr<ByteArray>>();
	return defaultValue;
}

double MslObject::optDouble(const string& key, double defaultValue) const
{
	Variant variant = opt(key);
	if (variant.isType<double>())
		return variant.get<double>();
	return defaultValue;
}

int32_t MslObject::optInt(const string& key, int32_t defaultValue) const
{
	Variant variant = opt(key);
	if (variant.isType<int32_t>())
		return variant.get<int32_t>();
	return defaultValue;
}

shared_ptr<MslArray> MslObject::optMslArray(const string& key) const
{
	Variant variant = opt(key);
	if (variant.isType<shared_ptr<MslArray>>())
		return variant.get<shared_ptr<MslArray>>();
	return shared_ptr<MslArray>();
}

shared_ptr<MslObject> MslObject::optMslObject(const string& key, shared_ptr<MslEncoderFactory> encoder) const
{
	Variant variant = opt(key);
	if (variant.isType<shared_ptr<MslObject>>())
		return variant.get<shared_ptr<MslObject>>();
	if (variant.isType<shared_ptr<ByteArray>>()) {
		try {
			encoder->parseObject(variant.get<shared_ptr<ByteArray>>());
		} catch (const MslEncoderException& e) {
			return shared_ptr<MslObject>();
		}
	}
	return shared_ptr<MslObject>();
}

int64_t MslObject::optLong(const string& key, int64_t defaultValue) const
{
	Variant variant = opt(key);
	if (variant.isType<int64_t>())
		return variant.get<int64_t>();
	return defaultValue;
}

string MslObject::optString(const string& key, const string& defaultValue) const
{
	Variant variant = opt(key);
	if (variant.isType<string>())
		return variant.get<string>();
	return defaultValue;
}

Variant MslObject::remove(const string& key)
{
    if (key.empty())
        throw IllegalArgumentException("empty key");
    const Variant value = opt(key);
    map_->erase(key);
    return value;
}

bool MslObject::has(const string& key) const
{
    if (key.empty())
        throw IllegalArgumentException("empty key");
    return (map_->count(key) > 0);
}

vector<string> MslObject::getKeys() const
{
    vector<string> v;
    v.reserve(map_->size());
    for (MapType::const_iterator it = map_->begin(); it != map_->end(); ++it)
        v.push_back(it->first);
    return v;
}

string MslObject::toString() const
{
    ostringstream oss;
    bool addComma = false;
    oss << "{";
    for (MapType::const_iterator it = map_->begin(); it != map_->end(); ++it)
    {
        if (addComma) oss << ",";
        oss << MslEncoderFactory::quote(it->first) << ":";
        oss << it->second.toString(); // recurse
        addComma = true;
    }
    oss << "}";
    return oss.str();
}

bool operator==(const MslObject& a, const MslObject& b)
{
    if (a.map_.get() == b.map_.get())
        return true;  // both share same underlying object
    if (a.map_->size() != b.map_->size())
        return false;
    return *a.map_ == *b.map_; // defer to map::operator==
}

bool operator!=(const MslObject& a, const MslObject& b) {return !(a==b);}

ostream & operator<<(ostream &os, const MslObject& mo)
{
    return os << mo.toString();
}

ostream & operator<<(ostream &os, shared_ptr<MslObject> mo)
{
    return os << mo->toString();
}

} /* namespace io */
} /* namespace msl */
} /* namespace netflix */
