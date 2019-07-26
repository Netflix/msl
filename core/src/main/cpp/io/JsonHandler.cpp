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

#include <io/JsonHandler.h>
#include <rapidjson/error/en.h>
#include <rapidjson/reader.h>
#include <rapidjson/document.h>
#include <iostream>
#include <sstream>
#include <memory>

//#define DEBUG
#include <util/Debug.h>

namespace netflix {
namespace msl {
namespace io {

using namespace std;
using namespace rapidjson;

namespace {
#if DEBUG_JSON
    util::DEBUG myCout(cerr);
#else
    std::ostream os(NULL);
    util::Debug myCout(os);
#endif
}

JsonHandler::JsonHandler(shared_ptr<MslObject> mo)
: root_(ObjectHolder("root", mo))
, state_(kInObject)
, curDepth_(0)
, first_(true)
{}

JsonHandler::JsonHandler(shared_ptr<MslArray> ma)
: root_(ObjectHolder("root", ma))
, state_(kInArray)
, curDepth_(0)
, first_(true)
{}

// FIXME:: Enforce max array length?

bool JsonHandler::StartObject()
{
    myCout << "StartObject()" << endl;
    if (first_) first_ = false;
    // If the stack is empty, start with the root. Otherwise make a new
    // MslObject.
    if (stack_.empty()) {
        if (state_ != kInObject)
            throw MslEncoderException("Expected object start");
        stack_.push(root_);
    } else {
        stack_.push(ObjectHolder(name_, make_shared<MslObject>()));
    }
    if (curDepth_++ > MAX_DEPTH)
        throw MslEncoderException("Max depth exceeded during JSON parsing");
    state_ = kInObject;
    return true;
}

bool JsonHandler::EndObject(SizeType memberCount)
{
    myCout << "EndObject(" << memberCount << ")" << endl;

    assert(state_ == kInObject);

    if (stack_.size() > 1)
    {
        // The finished object is on the top of the stack, save it.
        const ObjectHolder finished = stack_.top();
        const string finishedName = finished.name;
        assert (finished.obj.isType<shared_ptr<MslObject>>());
        shared_ptr<MslObject> finishedObject = finished.obj.get<shared_ptr<MslObject>>();
        assert(finishedObject->size() == memberCount);

        // Discard the top stack element now that we are done with it.
        stack_.pop();
        curDepth_--;

        // Add the finished object to the now current top object after the
        // pop. When we popped the stack we moved to a different object,
        // which may be either a MslObject or a MslArray. Call the correct
        // method to add the finished object to it, and update the current
        // state.
        Variant top = stack_.top().obj;
        if (top.isType<shared_ptr<MslObject>>()) {
            shared_ptr<MslObject> mslObject = top.get<shared_ptr<MslObject>>();
            mslObject->put<shared_ptr<MslObject>>(finishedName, finishedObject);
            state_ = kInObject;
        }
        else if (top.isType<shared_ptr<MslArray>>()) {
            shared_ptr<MslArray> mslArray = top.get<shared_ptr<MslArray>>();
            mslArray->put<shared_ptr<MslObject>>(-1, finishedObject);
            state_ = kInArray;
        }
        else {
            assert(false);
        }
    }
    return true;
}

bool JsonHandler::StartArray()
{
    myCout << "StartArray()" << endl;
    if (first_) first_ = false;
    // If the stack is empty, start with the root. Otherwise make a new
    // MslArray.
    if (stack_.empty()) {
        if (state_ != kInArray)
            throw MslEncoderException("Expected array start");
        stack_.push(root_);
    } else {
        stack_.push(ObjectHolder(name_, make_shared<MslArray>()));
    }
    if (curDepth_++ > MAX_DEPTH)
        throw MslEncoderException("Max depth exceeded during JSON parsing");
    state_ = kInArray;
    return true;
}

bool JsonHandler::EndArray(SizeType elementCount)
{
    myCout << "EndArray(" << elementCount << ")" << endl;
    assert(state_ == kInArray);

    if (stack_.size() > 1)
    {
        // The finished object is on the top of the stack, save it.
        const ObjectHolder finished = stack_.top();
        const string finishedName = finished.name;
        assert (finished.obj.isType<shared_ptr<MslArray>>());
        shared_ptr<MslArray> finishedObject = finished.obj.get<shared_ptr<MslArray>>();
        assert(finishedObject->size() == elementCount);

        // Discard the top stack element now that we are done with it.
        stack_.pop();
        curDepth_--;

        // Add the finished object to the now current top object after the
        // pop. When we popped the stack we moved to a different object,
        // which may be either a MslObject or a MslArray. Call the correct
        // method to add the finished object to it, and update the current
        // state.
        Variant top = stack_.top().obj;
        if (top.isType<shared_ptr<MslObject>>()) {
            shared_ptr<MslObject> mslObject = top.get<shared_ptr<MslObject>>();
            mslObject->put<shared_ptr<MslArray>>(finishedName, finishedObject);
            state_ = kInObject;
        }
        else if (top.isType<shared_ptr<MslArray>>()) {
            shared_ptr<MslArray> mslArray = top.get<shared_ptr<MslArray>>();
            mslArray->put<shared_ptr<MslArray>>(-1, finishedObject);
            state_ = kInArray;
        }
        else {
            assert(false);
        }
    }
    return true;
}

bool JsonHandler::Key(const char* str, SizeType length, bool copy)
{
    myCout << "Key(" << string(str) << ", " << length << ", " << boolalpha << copy << ")" << endl;
    if (first_)
        throw MslEncoderException("Found bad JSON state");
    name_ = string(str, length);
    return true;
}

bool JsonHandler::String(const char* str, SizeType length, bool copy)
{
    myCout << "String(" << string(str) << ", " << length << ", " << boolalpha << copy << ")" << endl;
    if (first_)
        throw MslEncoderException("Found bad JSON state");
    const string strVal = string(str, length);
    setTopVal(VariantFactory::create<string>(strVal));
    return true;
}

bool JsonHandler::Null()
{
    myCout << "Null()" << endl;
    if (first_)
        throw MslEncoderException("Found bad JSON state");
    setTopVal(VariantFactory::createNull());
    return true;
}

bool JsonHandler::Bool(bool b)
{
    myCout << "Bool(" << boolalpha << b << ")" << endl;
    if (first_)
        throw MslEncoderException("Found bad JSON state");
    setTopVal(VariantFactory::create<bool>(b));
    return true;
}

bool JsonHandler::Int(int i)
{
    myCout << "Int(" << i << ")" << endl;
    if (first_)
        throw MslEncoderException("Found bad JSON state");
    setTopVal(VariantFactory::create<int32_t>(i));
    return true;
}

bool JsonHandler::Uint(unsigned u)
{
    myCout << "Uint(" << u << ")" << endl;
    if (first_)
        throw MslEncoderException("Found bad JSON state");
    setTopVal(VariantFactory::create<int64_t>(u));
    return true;
}

bool JsonHandler::Int64(int64_t i)
{
    myCout << "Int64(" << i << ")" << endl;
    if (first_)
        throw MslEncoderException("Found bad JSON state");
    setTopVal(VariantFactory::create<int64_t>(i));
    return true;
}

bool JsonHandler::Uint64(uint64_t u)
{
    myCout << "Uint64(" << u << ")" << endl;
    if (first_)
        throw MslEncoderException("Found bad JSON state");
    setTopVal(VariantFactory::create<double>(static_cast<double>(u)));
    return true;
}

bool JsonHandler::Double(double d)
{
    myCout << "Double(" << d << ")" << endl;
    if (first_)
        throw MslEncoderException("Found bad JSON state");
    setTopVal(VariantFactory::create<double>(d));
    return true;
}

bool JsonHandler::RawNumber(const char* str, SizeType length, bool copy)
{
    myCout << "Number(" << string(str) << ", " << length << ", " << boolalpha << copy << ")" << endl;
    if (first_)
        throw MslEncoderException("Found bad JSON state");
    assert(true);
    return false;
}

bool JsonHandler::Default()
{
    return false; // All other events are invalid.
}

void JsonHandler::setTopVal(const Variant& val)
{
    assert(!stack_.empty());
    Variant top = stack_.top().obj;
    switch (state_)
    {
        case kInObject:
        {
            assert(top.isType<shared_ptr<MslObject>>());
            top.get<shared_ptr<MslObject>>()->put(name_, val);
            break;
        }
        case kInArray:
        {
            assert(top.isType<shared_ptr<MslArray>>());
            top.get<shared_ptr<MslArray>>()->put(-1, val);
            break;
        }
        default:
            assert(false);
    }
}

} /* namespace io */
} /* namespace msl */
} /* namespace netflix */
