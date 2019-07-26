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

#ifndef SRC_IO_MSLOBJECT_H_
#define SRC_IO_MSLOBJECT_H_

#include <io/MslEncoderException.h>
#include <io/MslVariant.h>
#include <util/Base64.h>
#include <Macros.h>
#include <IllegalArgumentException.h>
#include <StaticAssert.h>
#include <cstddef>
#include <iosfwd>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace netflix {
namespace msl {
namespace io {

class MslEncoderFactory;

/**
 * <p>A {@code MslObject} is an unordered collection of name/value pairs. It is
 * functionally equivalent to a JSON object, in that it encodes the pair data
 * without imposing any specific order and may contain more or less pairs than
 * explicitly defined.</p>
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
class MslObject
{
public:
    typedef std::map<std::string, Variant> MapType;
    virtual ~MslObject() {}
    MslObject() : map_(std::make_shared<MapType>()) {}

    /**
     * Create a new {@code MslObject} from the given map.
     *
     * @param map the map of name/value pairs. This must be a map of
     *        {@code std::string}s onto {@code Variant}s. Map may be empty.
     */
    MslObject(const MapType& map);

    /**
     * <p>Put a key/value pair into the {@code MslObject}. If the value is
     * {@code null} the key will be removed.</p>
     *
     * @param key the key.
     * @param value the value. May be {@code null}.
     * @return this.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    virtual void put(const std::string& key, const Variant& value);
    template <typename T> void put(const std::string& key, const T& value);

    /**
     * Return the value associated with the specified key.
     *
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    virtual Variant get(const std::string& key) const;

    /**
     * Return the value associated with the specified key.
     *
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    virtual bool getBoolean(const std::string& key) const;

    /**
     * Return the value associated with the specified key.
     *
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    virtual std::shared_ptr<ByteArray> getBytes(const std::string& key) const;

    /**
     * Return the value associated with the specified key.
     *
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    virtual double getDouble(const std::string& key) const;

    /**
     * Return the value associated with the specified key.
     *
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    virtual int32_t getInt(const std::string& key) const;

    /**
     * Return the value associated with the specified key.
     *
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    virtual std::shared_ptr<MslArray> getMslArray(const std::string& key) const;

    /**
     * Return the value associated with the specified key.
     *
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    virtual std::shared_ptr<MslObject> getMslObject(const std::string& key, std::shared_ptr<MslEncoderFactory> encoder) const;

    /**
     * Return the value associated with the specified key.
     *
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    virtual int64_t getLong(const std::string& key) const;

    /**
     * Return the value associated with the specified key.
     *
     * @param key the key.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     * @throws MslEncoderException if there is no associated value of the
     *         proper type or the value is {@code null}.
     */
    virtual std::string getString(const std::string& key) const;

    /**
     * Return the value associated with the specified key or {@code null} if
     * the key is unknown or the value is an unsupported type.
     *
     * @param key the key.
     * @return the value. May be {@code null}.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    virtual Variant opt(const std::string& key) const;

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type. If not
     * specified the default value is false.
     *
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    virtual bool optBoolean(const std::string& key, bool defaultValue = false) const;

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type. If not
     * specified the default value is an empty byte array.
     *
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    virtual std::shared_ptr<ByteArray> optBytes(const std::string& key, std::shared_ptr<ByteArray> defaultValue = std::make_shared<ByteArray>()) const;

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type. If not
     * specified the default value is quiet NaN.
     *
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    virtual double optDouble(const std::string& key, double defaultValue = std::numeric_limits<double>::quiet_NaN()) const;

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type. If not
     * specified the default value is zero.
     *
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    virtual int32_t optInt(const std::string& key, int defaultValue = 0) const;

    /**
     * Return the {@code MslArray} associated with the specified key or
     * {@code null} if the key is unknown or the value is not of the correct
     * type.
     *
     * @param key the key.
     * @return the {@code MslArray} or {@code null}.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    virtual std::shared_ptr<MslArray> optMslArray(const std::string& key) const;

    /**
     * Return the {@code MslObject} associated with the specified key or
     * {@code null} if the key unknown or the value is not of the correct type.
     *
     * @param key the key.
     * @param encoder the MSL encoder factory.
     * @return the {@code MslObject} or {@code null}.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    virtual std::shared_ptr<MslObject> optMslObject(const std::string& key, std::shared_ptr<MslEncoderFactory> encoder) const;

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type. If not
     * specified the default value is zero.
     *
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    virtual int64_t optLong(const std::string& key, int64_t defaultValue = 0) const;

    /**
     * Return the value associated with the specified key or the default value
     * if the key is unknown or the value is not of the correct type. If not
     * specified the default value is the empty string.
     *
     * @param key the key.
     * @param defaultValue the default value.
     * @return the value.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    virtual std::string optString(const std::string& key, const std::string& defaultValue = "") const;

    /**
     * Return true if the specified key exists. The value may be {@code null}.
     *
     * @param key the key.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    virtual bool has(const std::string& key) const;

    /**
     * Remove a key and its associated value from the {@code MslObject}.
     *
     * @param key the key.
     * @return the removed value. May be {@code null}.
     * @throws IllegalArgumentException if the key is {@code null}.
     */
    virtual Variant remove(const std::string& key);

    /**
     * Return a vector of the {@code MslObject} keys.
     *
     * @return the vector of the {@code MslObject} keys.
     */
    virtual std::vector<std::string> getKeys() const;

    /**
     * Return a map of the {@code MslObject} contents. This is a copy of the
     * underlying contents of this MslObject, so modifications will not affect
     * this.
     *
     * @return the map of {@code MslObject} contents.
     */
    virtual std::map<std::string, Variant> getMap() const { return *map_; }

    /**
     * Return a string representation of this MSL object.
     *
     * @return the string representation of this MSL object.
     */
    virtual std::string toString() const;

    /**
     * Return the number of top-level elements in the MslObject. This call
     * returns the size of the key/value map and does not descend into any
     * values (which also may be MslObjects or MslArrays).
     *
     * @return the number of top-level elements in this
     */
    virtual size_t size() const { return map_->size(); }

protected:
    /** Object map. */
    std::shared_ptr<MapType> map_;

    friend bool operator==(const MslObject& a, const MslObject& b);
    friend std::ostream & operator<<(std::ostream &os, const MslObject& p);
};

/*
 * Non-member deep comparison operators
 */
bool operator==(const MslObject& a, const MslObject& b);
bool operator!=(const MslObject& a, const MslObject& b);

template <typename T>
void MslObject::put(const std::string& key, const T& value)
{
    STATIC_ASSERT(isAllowed<T>::value);
    put(key, VariantFactory::create<T>(value));
}

// operator<< for easier use with output
std::ostream & operator<<(std::ostream &os, const MslObject& mo);
std::ostream & operator<<(std::ostream &os, std::shared_ptr<MslObject> mo);

}}} // namespace netflix::msl::io

#endif /* SRC_IO_MSLOBJECT_H_ */
