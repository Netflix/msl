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
#include <io/MslEncoderException.h>
#include <io/MslEncoderFactory.h>
#include <io/MslObject.h>
#include <IllegalArgumentException.h>
#include<sstream>

using namespace std;

namespace netflix {
namespace msl {
namespace io {

MslArray::MslArray(const ListType& list) : list_(make_shared<ListType>())
{
    ListType newList(list);
    list_->swap(newList);
}

void MslArray::put(int index, const Variant& value)
{
    if (index < -1)
        throw IllegalArgumentException("MslArray index is negative.");

    ListType newList(*list_);  // operate on a copy

    // Fill with empty elements as necessary.
    if (index >= static_cast<int>(newList.size())) {
        const int nElms = index+1-static_cast<int>(newList.size());
        newList.insert(newList.end(), static_cast<size_t>(nElms), VariantFactory::createNull());
    }

    // Append if requested, otherwise replace.
    if (index == -1 || index == static_cast<int>(newList.size())) {
        newList.push_back(value);
    } else {
        newList.at(static_cast<size_t>(index)) = value;
    }

    list_->swap(newList); // commit the change
}

bool MslArray::isNull(int index) const
{
    if (index < 0 || index >= static_cast<int>(list_->size())) {
    	stringstream ss;
    	ss << "MslArray[" << index << "] is negative or exceeds array length.";
        throw IllegalArgumentException(ss.str());
    }
    return list_->at(static_cast<size_t>(index)).isNull();
}

Variant MslArray::get(int index) const
{
    if (isNull(index)) {
    	stringstream ss;
    	ss << "MslArray[" << index << "] is null.";
        throw MslEncoderException(ss.str());
    }
    return list_->at(static_cast<size_t>(index));
}

bool MslArray::getBoolean(int index) const
{
	Variant variant = get(index);
	if (variant.isType<bool>())
		return variant.get<bool>();
	stringstream ss;
	ss << "MslArray[" << index << "] is not a boolean.";
    throw MslEncoderException(ss.str());
}

shared_ptr<ByteArray> MslArray::getBytes(int index) const
{
	Variant variant = get(index);
	if (variant.isType<shared_ptr<ByteArray>>())
		return variant.get<shared_ptr<ByteArray>>();
	stringstream ss;
	ss << "MslArray[" << index << "] is not binary data.";
    throw MslEncoderException(ss.str());
}

double MslArray::getDouble(int index) const
{
	Variant variant = get(index);
	if (variant.isType<int32_t>())
		return static_cast<double>(variant.get<int32_t>());
	if (variant.isType<int64_t>())
		return static_cast<double>(variant.get<int64_t>());
	if (variant.isType<double>())
		return variant.get<double>();
	stringstream ss;
	ss << "MslArray[" << index << "] is not a number.";
    throw MslEncoderException(ss.str());
}

int32_t MslArray::getInt(int index) const
{
	Variant variant = get(index);
	if (variant.isType<int32_t>())
		return variant.get<int32_t>();
	if (variant.isType<int64_t>())
		return static_cast<int32_t>(variant.get<int64_t>());
	if (variant.isType<double>())
		return static_cast<int32_t>(variant.get<double>());
	stringstream ss;
	ss << "MslArray[" << index << "] is not a number.";
    throw MslEncoderException(ss.str());
}

shared_ptr<MslArray> MslArray::getMslArray(int index) const
{
	Variant variant = get(index);
	if (variant.isType<shared_ptr<MslArray>>())
		return variant.get<shared_ptr<MslArray>>();
	stringstream ss;
	ss << "MslArray[" << index << "] is not a MslArray.";
	throw MslEncoderException(ss.str());
}

shared_ptr<MslObject> MslArray::getMslObject(int index, shared_ptr<MslEncoderFactory> encoder) const
{
	Variant variant = get(index);
	if (variant.isType<shared_ptr<MslObject>>())
		return variant.get<shared_ptr<MslObject>>();
	if (variant.isType<shared_ptr<ByteArray>>()) {
		try {
			return encoder->parseObject(variant.get<shared_ptr<ByteArray>>());
		} catch (const MslEncoderException& e) {
			stringstream ss;
			ss << "MslArray[" << index << "] is not a MslObject.";
			throw MslEncoderException(ss.str());
    	}
	}
	stringstream ss;
	ss << "MslArray[" << index << "] is not a MslObject.";
	throw MslEncoderException(ss.str());
}

int64_t MslArray::getLong(int index) const
{
	Variant variant = get(index);
	if (variant.isType<int32_t>())
		return static_cast<int64_t>(variant.get<int32_t>());
	if (variant.isType<int64_t>())
		return variant.get<int64_t>();
	if (variant.isType<double>())
		return static_cast<int64_t>(variant.get<double>());
	stringstream ss;
	ss << "MslArray[" << index << "] is not a number.";
    throw MslEncoderException(ss.str());
}

string MslArray::getString(int index) const
{
	Variant variant = get(index);
	if (variant.isType<string>())
		return variant.get<string>();
	stringstream ss;
	ss << "MslArray[" << index << "] is not a string.";
    throw MslEncoderException(ss.str());
}

Variant MslArray::opt(int index) const
{
    if (index < 0 || index >= static_cast<int>(list_->size())) {
    	stringstream ss;
    	ss << "MslArray[" << index << "] is negative or exceeds array length.";
        throw IllegalArgumentException(ss.str());
    }
    return list_->at(static_cast<size_t>(index));
}

bool MslArray::optBoolean(int index, bool defaultValue) const
{
	Variant variant = opt(index);
	if (variant.isType<bool>())
		return variant.get<bool>();
	return defaultValue;
}

shared_ptr<ByteArray> MslArray::optBytes(int index, shared_ptr<ByteArray> defaultValue) const
{
	Variant variant = opt(index);
	if (variant.isType<shared_ptr<ByteArray>>())
		return variant.get<shared_ptr<ByteArray>>();
	return defaultValue;
}

double MslArray::optDouble(int index, double defaultValue) const
{
	Variant variant = opt(index);
	if (variant.isType<int32_t>())
		return static_cast<double>(variant.get<int32_t>());
	if (variant.isType<int64_t>())
		return static_cast<double>(variant.get<int64_t>());
	if (variant.isType<double>())
		return variant.get<double>();
	return defaultValue;
}

int32_t MslArray::optInt(int index, int32_t defaultValue) const
{
	Variant variant = opt(index);
	if (variant.isType<int32_t>())
		return variant.get<int32_t>();
	if (variant.isType<int64_t>())
		return static_cast<int32_t>(variant.get<int64_t>());
	if (variant.isType<double>())
		return static_cast<int32_t>(variant.get<double>());
	return defaultValue;
}

shared_ptr<MslArray> MslArray::optMslArray(int index) const
{
	Variant variant = opt(index);
	if (variant.isType<shared_ptr<MslArray>>())
		return variant.get<shared_ptr<MslArray>>();
	return shared_ptr<MslArray>();
}

shared_ptr<MslObject> MslArray::optMslObject(int index, shared_ptr<MslEncoderFactory> encoder) const
{
	Variant variant = opt(index);
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

int64_t MslArray::optLong(int index, int64_t defaultValue) const
{
	Variant variant = opt(index);
	if (variant.isType<int32_t>())
		return static_cast<int64_t>(variant.get<int32_t>());
	if (variant.isType<int64_t>())
		return variant.get<int64_t>();
	if (variant.isType<double>())
		return static_cast<int64_t>(variant.get<double>());
	return defaultValue;
}

string MslArray::optString(int index, const string& defaultValue) const
{
	Variant variant = opt(index);
	if (variant.isType<string>())
		return variant.get<string>();
	return defaultValue;
}

Variant MslArray::remove(int index)
{
    if (index < -1 || index >= static_cast<int>(list_->size())) {
    	stringstream ss;
    	ss << "MslArray[" << index << "] is negative or exceeds array length.";
        throw IllegalArgumentException(ss.str());
    }
    const int i = (index == -1) ? static_cast<int>(list_->size()) - 1 : index;
    const Variant value = opt(i);
    list_->erase(list_->begin()+i);
    return value;
}

std::string MslArray::toString() const
{
    std::ostringstream oss;
    bool addComma = false;
    oss << "[";
    for (ListType::const_iterator it = list_->begin(); it != list_->end(); ++it)
    {
        if (addComma) oss << ",";
        oss << it->toString(); // recurse
        addComma = true;
    }
    oss << "]";
    return oss.str();
}

bool operator==(const MslArray& a, const MslArray& b)
{
    if (a.list_.get() == b.list_.get())
        return true;  // both share same underlying object
    return *a.list_ == *b.list_;  // defer to std::vector::operator==
}

bool operator!=(const MslArray& a, const MslArray& b) {return !(a==b);}

std::ostream & operator<<(std::ostream &os, const MslArray& ma)
{
    return os << ma.toString();
}

} /* namespace io */
} /* namespace msl */
} /* namespace netflix */
