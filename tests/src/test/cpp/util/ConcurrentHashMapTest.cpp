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

#include <gtest/gtest.h>
#include <util/ConcurrentHashMap.h>
#include <memory>

// ConcurrentHashMap uses C++11, so C++11 is used here as well

using namespace std;
using namespace testing;

namespace netflix {
namespace msl {
namespace util {

namespace {

class KeyClass
{
public:
    KeyClass(size_t id) : id(id) {}
    bool equals(shared_ptr<KeyClass> other) { return id == other->id; }
private:
    size_t id;
};

struct ValueClass
{
public:
    ValueClass(size_t id) : id(id) {}
    const size_t id;
};
bool operator==(const ValueClass& a, const ValueClass& b) { return a.id == b.id; }

struct ComplexKeyClass
{
    ComplexKeyClass(size_t a, size_t b) : a(a), b(b) {}
    const size_t a;
    const size_t b;
};

typedef std::pair<std::shared_ptr<ComplexKeyClass>, std::shared_ptr<ValueClass>> PairType;
struct ComplexKeyPredicate : std::unary_function<PairType, bool>
{
    ComplexKeyPredicate(std::shared_ptr<ComplexKeyClass>& key) : key(key) {}
    bool operator()(const PairType& p) const { return p.first->b == key->b; }
    const std::shared_ptr<ComplexKeyClass>& key;
};

} // namespace anonymous

// TODO: For now this test just checks the interface; does not test concurrency
class ConcurrentHashMapTest : public ::testing::Test
{
};

TEST_F(ConcurrentHashMapTest, putIfAbsent)
{
    ConcurrentHashMap<KeyClass, ValueClass> map_;
    EXPECT_EQ(0u, map_.size());

    shared_ptr<KeyClass> key0 = make_shared<KeyClass>(0);
    shared_ptr<ValueClass> value0 = make_shared<ValueClass>(0);
    shared_ptr<ValueClass> value1 = make_shared<ValueClass>(1);

    // entry for key0 absent, add entry
    shared_ptr<ValueClass> putValue0 = map_.putIfAbsent(key0, value0);
    EXPECT_EQ(1u, map_.size());
    EXPECT_FALSE(putValue0);

    // entry for key0 is not absent, returns existing entry
    shared_ptr<ValueClass> putValue1 = map_.putIfAbsent(key0, value1);
    EXPECT_EQ(1u, map_.size());
    EXPECT_NE(value1, putValue1);
    EXPECT_EQ(value0, putValue1);

    map_.putIfAbsent(make_shared<KeyClass>(1), make_shared<ValueClass>(1));
}

TEST_F(ConcurrentHashMapTest, get)
{
    ConcurrentHashMap<KeyClass, ValueClass> map_;
    EXPECT_EQ(0u, map_.size());

    shared_ptr<KeyClass> key0 = make_shared<KeyClass>(0);
    shared_ptr<KeyClass> key1 = make_shared<KeyClass>(1);
    shared_ptr<ValueClass> value0 = make_shared<ValueClass>(0);

    map_.putIfAbsent(key0, value0);
    EXPECT_EQ(1u, map_.size());

    // get existing entry
    shared_ptr<ValueClass> getValue0 = map_.get(key0);
    EXPECT_TRUE(getValue0);
    EXPECT_EQ(value0, getValue0);
    EXPECT_EQ(*value0, *getValue0);

    // get missing entry
    shared_ptr<ValueClass> getValue1 = map_.get(key1);
    EXPECT_FALSE(getValue1);
}

TEST_F(ConcurrentHashMapTest, remove)
{
    // Load map
    ConcurrentHashMap<KeyClass, ValueClass> map_;
    EXPECT_EQ(0u, map_.size());
    for (size_t i=0; i < 10; ++i)
        map_.putIfAbsent(make_shared<KeyClass>(i), make_shared<ValueClass>(i));
    EXPECT_EQ(10u, map_.size());

    // Remove element
    shared_ptr<ValueClass> removed = map_.remove(make_shared<KeyClass>(5u));
    EXPECT_EQ(ValueClass(5u), *removed);
    EXPECT_EQ(9u, map_.size());

    // Remove the same element, must return empty shared_ptr
    removed = map_.remove(make_shared<KeyClass>(5u));
    EXPECT_FALSE(removed);
    EXPECT_EQ(9u, map_.size());

    map_.clear();
    EXPECT_EQ(0u, map_.size());
}

TEST_F(ConcurrentHashMapTest, customPredicate)
{
    ConcurrentHashMap<ComplexKeyClass, ValueClass, ComplexKeyPredicate> map_;
    EXPECT_EQ(0u, map_.size());
    for (size_t i=0; i < 10; ++i)
        map_.putIfAbsent(make_shared<ComplexKeyClass>(i+100, i), make_shared<ValueClass>(i));
    EXPECT_EQ(10u, map_.size());

    shared_ptr<ComplexKeyClass> goodKey5 = make_shared<ComplexKeyClass>(5u+100, 5u);
    shared_ptr<ComplexKeyClass> goodKey5_1 = make_shared<ComplexKeyClass>(5u+100+1, 5u);
    shared_ptr<ComplexKeyClass> badKey5 = make_shared<ComplexKeyClass>(5u+100, 5u+100);

    EXPECT_TRUE(map_.get(goodKey5));
    EXPECT_TRUE(map_.get(goodKey5_1));
    EXPECT_FALSE(map_.get(badKey5));
}

}}} // namespace netflix::msl::util
