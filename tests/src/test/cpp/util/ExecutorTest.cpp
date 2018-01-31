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
#include <util/Executor.h>
#include <cmath>
#include <functional>
#include <memory>

using namespace std;
using namespace testing;

namespace netflix {
namespace msl {
namespace util {

namespace {

int f(int x, int y) { return (int)pow(x,y); }

class Callable
{
public:
    explicit Callable(int ans) : ans(ans) {}
    int operator()() { return answer(); }
    int answer() const { return ans; }
private:
    const int ans;
};

}

class ExecutorTest : public ::testing::Test
{
};

TEST_F(ExecutorTest, sync)
{
    SynchronousExecutor executor;
    future<int> result;

    result = executor.submit(bind(f, 2, 11));
    EXPECT_EQ(2048, result.get());

    Callable callable(100);
    result = executor.submit(callable);
    EXPECT_EQ(callable.answer(), result.get());
}

TEST_F(ExecutorTest, async)
{
    AsynchronousExecutor executor;
    future<int> result1 = executor.submit(bind(f, 2, 12));
    EXPECT_EQ(4096, result1.get());

    const int NITS = 1000;
    vector<future<int>> result;
    for (int i=0; i<NITS; ++i)
        result.push_back(executor.submit(Callable(i)));

    for (int i=0; i<NITS; ++i)
        EXPECT_EQ(i, result[static_cast<size_t>(i)].get());
}

}}} // namespace netflix::msl::util
