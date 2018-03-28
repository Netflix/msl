/**
 * Copyright (c) 2018 Netflix, Inc.  All rights reserved.
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
#include <io/BufferedInputStream.h>
#include <crypto/Random.h>
#include <io/ByteArrayInputStream.h>
#include <IOException.h>
#include <algorithm>
#include <memory>
#include <vector>

using namespace std;
using namespace netflix::msl::crypto;

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace io {

namespace {

/**
 * A byte array input stream that counts the number of bytes read.
 */
class CountingByteArrayInputStream : public ByteArrayInputStream
{
public:
    virtual ~CountingByteArrayInputStream() {}

    /**
     * Create a new byte array input stream from the provided data.
     *
     * @param data the data.
     */
    CountingByteArrayInputStream(std::shared_ptr<ByteArray> data)
        : ByteArrayInputStream(data)
    {}

    /**
     * Create a new byte array input stream from the provided string.
     *
     * @param s the string.
     */
    CountingByteArrayInputStream(const std::string& s)
        : ByteArrayInputStream(s)
    {}

    /** @inheritDoc */
    virtual int read(ByteArray& out, int timeout = -1)
    {
        int count = ByteArrayInputStream::read(out, 0, out.size(), timeout);
        if (count != -1)
            readcount_ += count;
        return count;
    }

    /** @inheritDoc */
    virtual int read(ByteArray& out, size_t offset, size_t len, int timeout = -1)
    {
        int count = ByteArrayInputStream::read(out, offset, len, timeout);
        if (count != -1)
            readcount_ += count;
        return count;
    }

    /**
     * @return the number of bytes that have been read, including bytes that
     *         may have been read multiple times due to mark() and reset().
     */
    virtual size_t readCount() { return readcount_; }

    /**
     * @return the number of additional bytes that can be read before reaching
     *         end of stream.
     */
    virtual size_t available() { return static_cast<size_t>(data_->size()) - currentPosition_; }

protected:
    /** Number of bytes read. */
    size_t readcount_ = 0;
};
} // namespace anonymous

class BufferedInputStreamTest : public ::testing::Test
{
public:
    virtual ~BufferedInputStreamTest() {}

    BufferedInputStreamTest()
    {
        data = make_shared<ByteArray>(123456);
        Random r;
        r.nextBytes(*data);
        cbais = make_shared<CountingByteArrayInputStream>(data);
    }

protected:
    shared_ptr<ByteArray> data;
    shared_ptr<CountingByteArrayInputStream> cbais;
};

TEST_F(BufferedInputStreamTest, ReadDefault)
{
    const size_t readSize = BufferedInputStream::DEFAULT_READ_SIZE;
    BufferedInputStream bis(cbais);

    // Nothing should be read yet.
    EXPECT_EQ(static_cast<size_t>(0), cbais->readCount());
    EXPECT_EQ(data->size(), cbais->available());

    // Reading one byte should result in a larger number of bytes equal to the
    // default read size being read.
    ByteArray one(1);
    int oneCount = bis.read(one);
    EXPECT_EQ(one.size(), static_cast<size_t>(oneCount));
    EXPECT_TRUE(equal(data->begin(), data->begin() + oneCount, one.begin()));
    EXPECT_EQ(readSize, cbais->readCount());
    EXPECT_EQ(data->size() - readSize, cbais->available());

    // Reading more bytes up to the default read size should not result in
    // additional reads against the backing source.
    ByteArray remaining(readSize - one.size());
    int remainingCount = bis.read(remaining);
    EXPECT_EQ(remaining.size(), static_cast<size_t>(remainingCount));
    EXPECT_TRUE(equal(data->begin() + oneCount, data->begin() + remainingCount, remaining.begin()));
    EXPECT_EQ(readSize, cbais->readCount());
    EXPECT_EQ(data->size() - readSize, cbais->available());

    // Reading more than the default read size should read at least that much
    // from the backing source.
    ByteArray large(readSize + 1);
    int largeCount = bis.read(large);
    EXPECT_EQ(large.size(), static_cast<size_t>(largeCount));
    EXPECT_TRUE(equal(data->begin() + oneCount + remainingCount, data->begin() + oneCount + remainingCount + largeCount, large.begin()));
    EXPECT_LE(large.size(), cbais->readCount());
    EXPECT_EQ(data->size() - cbais->readCount(), cbais->available());
}

TEST_F(BufferedInputStreamTest, ReadSmall)
{
    const size_t readSize = 32;
    BufferedInputStream bis(cbais, readSize);

    // Nothing should be read yet.
    EXPECT_EQ(static_cast<size_t>(0), cbais->readCount());
    EXPECT_EQ(data->size(), cbais->available());

    // Reading one byte should result in a larger number of bytes equal to the
    // default read size being read.
    ByteArray one(1);
    int oneCount = bis.read(one);
    EXPECT_EQ(one.size(), static_cast<size_t>(oneCount));
    EXPECT_TRUE(equal(data->begin(), data->begin() + oneCount, one.begin()));
    EXPECT_EQ(readSize, cbais->readCount());
    EXPECT_EQ(data->size() - readSize, cbais->available());

    // Reading more bytes up to the default read size should not result in
    // additional reads against the backing source.
    ByteArray remaining(readSize - one.size());
    int remainingCount = bis.read(remaining);
    EXPECT_EQ(remaining.size(), static_cast<size_t>(remainingCount));
    EXPECT_TRUE(equal(data->begin() + oneCount, data->begin() + remainingCount, remaining.begin()));
    EXPECT_EQ(readSize, cbais->readCount());
    EXPECT_EQ(data->size() - readSize, cbais->available());

    // Reading more than the default read size should read at least that much
    // from the backing source.
    ByteArray large(readSize + 1);
    int largeCount = bis.read(large);
    EXPECT_EQ(large.size(), static_cast<size_t>(largeCount));
    EXPECT_TRUE(equal(data->begin() + oneCount + remainingCount, data->begin() + oneCount + remainingCount + largeCount, large.begin()));
    EXPECT_LE(large.size(), cbais->readCount());
    EXPECT_EQ(data->size() - cbais->readCount(), cbais->available());
}

TEST_F(BufferedInputStreamTest, MarkReset)
{
    const size_t readSize = 32;
    BufferedInputStream bis(cbais, readSize);

    // Mark at zero and read one byte.
    bis.mark(2 * readSize);
    ByteArray one(1);
    int oneCount = bis.read(one);
    EXPECT_EQ(one.size(), static_cast<size_t>(oneCount));
    EXPECT_TRUE(equal(data->begin(), data->begin() + oneCount, one.begin()));
    EXPECT_EQ(readSize, cbais->readCount());
    EXPECT_EQ(data->size() - readSize, cbais->available());

    // Reset and read a chunk worth of bytes. No bytes should have been read
    // off the backing source.
    bis.reset();
    ByteArray chunk(readSize);
    int chunkCount = bis.read(chunk);
    EXPECT_EQ(chunk.size(), static_cast<size_t>(chunkCount));
    EXPECT_TRUE(equal(data->begin(), data->begin() + chunkCount, chunk.begin()));
    EXPECT_EQ(readSize, cbais->readCount());
    EXPECT_EQ(data->size() - readSize, cbais->available());

    // Read another byte. Another chunk's worth of bytes should have been read
    // off the backing source.
    chunkCount = bis.read(chunk);
    EXPECT_EQ(chunk.size(), static_cast<size_t>(chunkCount));
    EXPECT_TRUE(equal(data->begin() + chunkCount, data->begin() + 2 * chunkCount, chunk.begin()));
    EXPECT_EQ(2 * readSize, cbais->readCount());
    EXPECT_EQ(data->size() - 2 * readSize, cbais->available());
}

TEST_F(BufferedInputStreamTest, InvalidateMark)
{
    const size_t readSize = 32;
    BufferedInputStream bis(cbais, readSize);

    // Mark with a read limit half the chunk size.
    bis.mark(readSize / 2);

    // Read a chunk. This should invalidate the mark.
    ByteArray chunk(readSize);
    int chunkCount = bis.read(chunk);
    EXPECT_EQ(chunk.size(), static_cast<size_t>(chunkCount));
    EXPECT_TRUE(equal(data->begin(), data->begin() + chunkCount, chunk.begin()));
    EXPECT_EQ(readSize, cbais->readCount());
    EXPECT_EQ(data->size() - readSize, cbais->available());

    // Reset should throw an exception.
    EXPECT_THROW(bis.reset(), IOException);
}

}}} // namespace netflix::msl::io
