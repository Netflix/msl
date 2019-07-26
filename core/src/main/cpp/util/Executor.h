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

#ifndef SRC_UTIL_EXECUTOR_H_
#define SRC_UTIL_EXECUTOR_H_

//#define USE_THREADPOOL

#include <future>
#ifdef USE_THREADPOOL
#include <util/ThreadPool.h>
#endif

namespace netflix {
namespace msl {
namespace util {

class Executor
{
public:
    virtual ~Executor() {}
    virtual void shutdown() = 0;
    template <typename FunctionType>
    std::future<typename std::result_of<FunctionType()>::type> submit(FunctionType f)
    {
        if (isSynchronous()) {
            typedef typename std::result_of<FunctionType()>::type ResultType;
            std::packaged_task<ResultType()> task(std::move(f));
            std::future<ResultType> result(task.get_future());
            task();
            return result;
        } else {
            // TODO: Figure out how to cancel the async task. Consider making a
            // shared cancellation object here, pass to the task and also return
            // to the caller along with the future.
#ifdef USE_THREADPOOL
            return threadpool->submit(f);
#else
            return std::async(std::launch::async, f);
#endif
        }
    }
protected:
    virtual bool isSynchronous() = 0;
#ifdef USE_THREADPOOL
    void startThreadPool() { threadpool = std::unique_ptr<util::ThreadPool>(new ThreadPool()); }
    std::unique_ptr<util::ThreadPool> threadpool;
#endif
};

class SynchronousExecutor : public Executor
{
public:
    virtual bool isSynchronous() override { return true; }
    virtual void shutdown() override {};
};

class AsynchronousExecutor : public Executor
{
public:
    AsynchronousExecutor()
    {
#ifdef USE_THREADPOOL
        startThreadPool();
#endif
    }
    virtual bool isSynchronous() override { return false; }
    virtual void shutdown() override {};  // FIXME: can't stop std::async
};

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_EXECUTOR_H_ */
