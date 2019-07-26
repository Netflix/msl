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

#ifndef VARIANT_H_
#define VARIANT_H_

#include <Exception.h>
#include <stddef.h>
#include <StaticAssert.h>
#include <memory>
#include <typeinfo>
#include <vector>

namespace netflix {
namespace msl {

typedef std::vector<uint8_t> ByteArray;

namespace io {

class MslArray;
class MslEncodable;
class MslObject;
class Variant;

// Detect Variant type to trigger a STATIC_ASSERT if placed into a Variant.
template<typename T> struct isVariant{ static const int value = false; };
template<> struct isVariant<Variant>{ static const int value = true; };

// Do-nothing class to indicate null Variants
class Null {};

// List of specific types allowed in Variant. If any other type is used, it will
// trigger a (compile time) STATIC_ASSERT. This list matches the types in the
// visit method overloads in the VariantVisitor interface below.
typedef std::vector<uint8_t> ByteArray;
template<typename T> struct isAllowed{ static const int value = false; };
template<> struct isAllowed<Null>{ static const int value = true; };
template<> struct isAllowed<std::string>{ static const int value = true; };
template<> struct isAllowed<int32_t>{ static const int value = true; };
template<> struct isAllowed<bool>{ static const int value = true; };
template<> struct isAllowed<int64_t>{ static const int value = true; };
template<> struct isAllowed<double>{ static const int value = true; };
template<> struct isAllowed<std::shared_ptr<ByteArray>>{ static const int value = true; };
template<> struct isAllowed<std::shared_ptr<MslObject>>{ static const int value = true; };
template<> struct isAllowed<std::shared_ptr<MslArray>>{ static const int value = true; };
template<> struct isAllowed<std::shared_ptr<MslEncodable>>{ static const int value = true; };

struct VariantVisitor
{
    virtual ~VariantVisitor() {}
    virtual void visit(const Null& x) = 0;
    virtual void visit(const std::string& x) = 0;
    virtual void visit(bool x) = 0;
    virtual void visit(int32_t x) = 0;
    virtual void visit(int64_t x) = 0;
    virtual void visit(double x) = 0;
    virtual void visit(std::shared_ptr<ByteArray> x) = 0;
    virtual void visit(std::shared_ptr<MslObject> x) = 0;
    virtual void visit(std::shared_ptr<MslArray> x) = 0;
    virtual void visit(std::shared_ptr<MslEncodable> x) = 0;
};

namespace variantdetail
{

class B
{
public:
    virtual ~B() {}
    virtual size_t getHashCode() const = 0;
    virtual bool isEqual(const B* rhs) const = 0;
    virtual void accept(VariantVisitor& visitor) const = 0;
};

// T must: 1. have copy ctor, 2. have operator==, and 3. not be a Variant
template<typename T>
class D : public B
{
public:
    virtual ~D() {}
    explicit D(const T& value)
        : hashCode_(typeid(value).hash_code()), value_(value)
    {
        STATIC_ASSERT(!isVariant<T>::value);
        STATIC_ASSERT(isAllowed<T>::value);
    }
    T value() const { return value_; }
    virtual size_t getHashCode() const {return hashCode_;};
    virtual bool isEqual(const B* rhs) const
    {
        const D* d = dynamic_cast<const D*>(rhs);
        if (!d) return false;
        return value_ == d->value_; // invokes T's operator==
    }
    virtual void accept(VariantVisitor& visitor) const {
        visitor.visit(value_);
    }
    // default copy ctor and assignment operators ok
private:
    const size_t hashCode_;
    const T value_;
};

} // namespace variantdetail

class Variant
{
public:
    // Default copy ctor and operator= are ok, they copy the member shared_ptr
    // with no_throw guarantee.
    // NOTE: Sharing semantics are intended: a copy of a Variant should point to
    // the same underlying object.
    template<typename T> bool isType() const {
        return (value_->getHashCode() == typeid(T).hash_code());
    }
    template<typename T> T get() const {
        if (!isType<T>()) throw Exception(std::bad_cast());
        return std::static_pointer_cast<variantdetail::D<T> >(value_)->value();
    }
    template<typename T> T getOpt() const {
        if (!isType<T>()) return T();
        return std::static_pointer_cast<variantdetail::D<T> >(value_)->value();
    }
    size_t getHashCode() const { return value_->getHashCode(); }
    bool isNull() const { return isType<Null>(); }
    std::string toString() const;
    void accept(VariantVisitor& visitor) const;
private:
    Variant(); // not implemented
    explicit Variant(std::shared_ptr<variantdetail::B> value) : value_(value) {}
    std::shared_ptr<variantdetail::B> value_;
    friend struct VariantFactory;
    friend bool operator==(const Variant&, const Variant&);
};

struct VariantFactory
{
    static Variant createNull() {
        return Variant(std::shared_ptr<variantdetail::B>(std::make_shared<variantdetail::D<Null>>(Null())));
    }
    template<typename T>
    static Variant create(const T& value) {
        return Variant(std::shared_ptr<variantdetail::B>(std::make_shared<variantdetail::D<T>>(value)));
    }
};

bool operator==(const Variant& a, const Variant& b);
bool operator!=(const Variant& a, const Variant& b);

bool operator==(const Null& a, const Null& b);
bool operator==(std::shared_ptr<ByteArray> a, std::shared_ptr<ByteArray> b);
bool operator==(std::shared_ptr<MslObject> a, std::shared_ptr<MslObject> b);
bool operator==(std::shared_ptr<MslArray> a, std::shared_ptr<MslArray> b);
//bool operator==(std::shared_ptr<MslEncodable> a, std::shared_ptr<MslEncodable> b);

}}} /* namespace netflix::msl::io */

#endif /* VARIANT_H_ */
