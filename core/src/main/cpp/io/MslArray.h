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

#ifndef SRC_IO_MSLARRAY_H_
#define SRC_IO_MSLARRAY_H_

#include <io/MslEncoderException.h>
#include <io/MslVariant.h>
#include <stddef.h>
#include <StaticAssert.h>
#include <limits>
#include <list>
#include <set>

namespace netflix {
namespace msl {
namespace io {
class MslEncoderFactory;

/**
 * <p>A {@code MslArray} is an ordered sequence of values.</p>
 *
 * <p>The values are of type Variant, which in turn can hold a value of any
 * type. In practice, MslObject will contain only types from the following
 * set: { <code>ByteArray</code>, <code>shared_ptr<MslArray></code>,
 * <code>shared_ptr<MslObject></code>, <code>std::string</code>, and C numeric
 * types.</p>
 *
 * <p>The generic <code>get()</code> and <code>opt()</code> methods return
 * a Variant, which you can query for type and extract the underlying value.
 * There are also typed <code>get</code> and <code>opt</code> methods that do
 * type checking and type coercion for you. The opt methods differ from the get
 * methods in that they do not throw. Instead, they return either a default-
 * constructed value of the requested type, or a user-provided default.</p>
 *
 * <p>The <code>put</code> methods add or replace values in an object.</p>
 */
class MslArray
{
public:
    typedef std::vector<Variant> ListType;
    virtual ~MslArray() {}

    /**
     * Create a new empty {@code MslArray}.
     */
    MslArray() : list_(std::make_shared<ListType>()) {}

    /**
     * Create a new {@code MslArray} from the given list.
     *
     * @param list the list of values. May be empty.
     */
    MslArray(const ListType& list);

    /**
     * Create a new {@code MslArray} from the given list. The type inside the
     * container must not be a Variant
     *
     * @param list the list of values. May be empty.
     */
    template <typename T> MslArray(const std::vector<T>& list) {
        MslArray newMslArray;
        for (typename std::vector<T>::const_iterator it = list.begin(); it != list.end(); ++it)
            newMslArray.put<T>(-1, *it);
        list_.swap(newMslArray.list_);
    }

    /**
     * Create a new {@code MslArray} from the given list. The type inside the
     * container must not be a Variant
     *
     * @param list the list of values. May be empty.
     */
    template <typename T> MslArray(const std::list<T>& list) {
        MslArray newMslArray;
        for (typename std::list<T>::const_iterator it = list.begin(); it != list.end(); ++it)
            newMslArray.put<T>(-1, *it);
        list_.swap(newMslArray.list_);
    }

    /**
     * Create a new {@code MslArray} from the given set. The type inside the
     * container must not be a Variant.
     *
     * @param list the list of values. May be empty.
     */
    template <typename T> MslArray(const std::set<T>& set) {
        MslArray newMslArray;
        for (typename std::set<T>::const_iterator it = set.begin(); it != set.end(); ++it)
            newMslArray.put<T>(-1, *it);
        list_.swap(newMslArray.list_);
    }

    // Default copy ctor and operator= are ok.
    // NOTE: Sharing semantics are intended: a copy of a MslArray will point
    // to the original underlying ref-counted data.

    /**
     * Return true if the value at the index is {@code null}.
     *
     * @param index the index.
     * @return true if the value is null.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    virtual bool isNull(int index) const;

    /**
     * <p>Put or replace a value in the {@code MslArray} at the index. If the
     * index exceeds the length, null elements will be added as necessary.</p>
     *
     * @param index the index. -1 for the end of the array.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the index is less than -1.
     */
    virtual void put(int index, const Variant& value);
    template <typename T> void put(int index, const T& value);

    /**
     * Return the value associated with an index.
     *
     * @param index the index.
     * @return the value.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    virtual Variant get(int index) const;

    /**
     * Return the value associated with an index.
     *
     * @param index the index.
     * @return the value.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    virtual bool getBoolean(int index) const;

    /**
     * Return the value associated with an index.
     *
     * @param index the index.
     * @return the value.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    virtual std::shared_ptr<ByteArray> getBytes(int index) const;

    /**
     * Return the value associated with an index.
     *
     * @param index the index.
     * @return the value.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    virtual double getDouble(int index) const;

    /**
     * Return the value associated with an index.
     *
     * @param index the index.
     * @return the value.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    virtual int32_t getInt(int index) const;

    /**
     * Return the value associated with an index.
     *
     * @param index the index.
     * @return the value.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    virtual std::shared_ptr<MslArray> getMslArray(int index) const;

    /**
     * Return the value associated with an index.
     *
     * @param index the index.
     * @return the value.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    virtual std::shared_ptr<MslObject> getMslObject(int index, std::shared_ptr<MslEncoderFactory> encoder) const;

    /**
     * Return the value associated with an index.
     *
     * @param index the index.
     * @return the value.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    virtual int64_t getLong(int index) const;

    /**
     * Return the value associated with an index.
     *
     * @param index the index.
     * @return the value.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     * @throws MslEncoderException if the value is {@code null} or of the wrong
     *         type.
     */
    virtual std::string getString(int index) const;

    /**
     * Return the value at the index, which may be {@code null}. {@code null}
     * will also be returned if the value is an unsupported type.
     *
     * @param index the index.
     * @return the value. May be {@code null}.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    Variant opt(int index) const;

    /**
     * Return the value at the index or the default value if the value is not
     * of the correct type. If not specified the default value is false.
     *
     * @param index the index.
     * @param defaultValue the default value.
     * @return the value. May be {@code null}.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    virtual bool optBoolean(int index, bool defaultValue = false) const;

    /**
     * Return the value at the index or the default value if the value is not
     * of the correct type. If not specified the default value is an empty byte
     * array.
     *
     * @param index the index.
     * @param defaultValue the default value.
     * @return the value. May be {@code null}.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    virtual std::shared_ptr<ByteArray> optBytes(int index, std::shared_ptr<ByteArray> defaultValue = std::make_shared<ByteArray>()) const;

    /**
     * Return the value at the index or the default value if the value is not
     * of the correct type. If not specified the default value is quiet NaN.
     *
     * @param index the index.
     * @param defaultValue the default value.
     * @return the value. May be {@code null}.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    virtual double optDouble(int index, double defaultValue = std::numeric_limits<double>::quiet_NaN()) const;

    /**
     * Return the value at the index or the default value if the value is not
     * of the correct type. If not specified the default value is zero.
     *
     * @param index the index.
     * @param defaultValue the default value.
     * @return the value. May be {@code null}.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    virtual int32_t optInt(int index, int defaultValue = 0) const;

    /**
     * Return the {@code MslArray} at the index or {@code null} if the value
     * is not of the correct type.
     *
     *
     * @param index the index.
     * @return the {@code MslArray} or {@code null}.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    virtual std::shared_ptr<MslArray> optMslArray(int index) const;

    /**
     * Return the {@code MslObject} at the index or {@code null} if the value
     * is not of the correct type.
     *
     * @param index the index.
     * @param encoder the MSL encoder factory.
     * @return the {@code MslObject} or {@code null}.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    virtual std::shared_ptr<MslObject> optMslObject(int index, std::shared_ptr<MslEncoderFactory> encoder) const;

    /**
     * Return the value at the index or the default value if the value is not
     * of the correct type. If not specified the default value is zero.
     *
     * @param index the index.
     * @param defaultValue the default value.
     * @return the value. May be {@code null}.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    virtual int64_t optLong(int index, int64_t defaultValue = 0) const;

    /**
     * Return the value at the index or the default value if the value is not
     * of the correct type. If not specified the default value is the empty
     * string.
     *
     * @param index the index.
     * @param defaultValue the default value.
     * @return the value. May be {@code null}.
     * @throws IllegalArgumentException if the index is negative or
     *         exceeds the number of elements in the array.
     */
    virtual std::string optString(int index, const std::string& defaultValue = "") const;

    /**
     * Remove an element at the index. This decreases the length by one.
     *
     * @param index the index. -1 for the end of the array.
     * @return the removed value. May be {@code null}.
     * @throws IllegalArgumentException if the index is negative or exceeds
     *         exceeds the number of elements in the array.
     */
    virtual Variant remove(int index);

    /**
     * Return a copy of the {@code MslArray} contents.
     *
     * @return a copy of {@code MslArray} contents.
     */
    virtual std::vector<Variant> getCollection() const {
        return *list_;
    }

    /**
     * Return a string representation of this MSL object.
     *
     * @return the string representation of this MSL object.
     */
    virtual std::string toString() const;

    /**
     * Return the number of top-level elements in the MslArray. This call
     * returns the size of the list and does not descend into any values (which
     * also may be MslObjects or MslArrays).
     *
     * @return the number of top-level elements in this
     */
    virtual size_t size() const { return list_->size(); }

protected:
    std::shared_ptr<ListType> list_;
    friend bool operator==(const MslArray& a, const MslArray& b);
};

/*
 * Non-member deep comparison operators
 */
bool operator==(const MslArray& a, const MslArray& b);
bool operator!=(const MslArray& a, const MslArray& b);

template <typename T>
void MslArray::put(int index, const T& value) {
	STATIC_ASSERT(isAllowed<T>::value);
	put(index, VariantFactory::create<T>(value));
}

// operator<< for easier use with output
std::ostream & operator<<(std::ostream &os, const MslArray& ma);

}}} // namespace netflix::msl::io

#endif /* SRC_IO_MSLARRAY_H_ */
