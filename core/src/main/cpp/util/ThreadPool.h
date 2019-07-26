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

#ifndef SRC_UTIL_THREADPOOL_H_
#define SRC_UTIL_THREADPOOL_H_

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace netflix {
namespace msl {
namespace util {

template <typename T>
class ThreadSafeQueue
{
public:
    ThreadSafeQueue() {}
    ~ThreadSafeQueue() { clear(); }
    void waitPop(T& value)
    {
        std::unique_lock<std::mutex> lock(mut);
        dataCond.wait(lock, [this] {return !dataQueue.empty();});
        value = std::move(*dataQueue.front());
        dataQueue.pop();
    }
    bool tryPop(T& value)
    {
        std::lock_guard<std::mutex> lock(mut);
        if (dataQueue.empty())
            return false;
        value = std::move(*dataQueue.front());
        dataQueue.pop();
        return true;
    }
    void push(T newValue)
    {
        std::shared_ptr<T> data(std::make_shared<T>(std::move(newValue)));
        std::lock_guard<std::mutex> lock(mut);
        dataQueue.push(data);
        dataCond.notify_one();
    }
    bool empty() const
    {
        std::lock_guard<std::mutex> lock(mut);
        return dataQueue.empty();
    }
    void clear()
    {
        std::lock_guard<std::mutex> lock(mut);
        std::queue<std::shared_ptr<T>> empty;
        std::swap(dataQueue, empty);
    }
private:
    mutable std::mutex mut;
    std::queue<std::shared_ptr<T>> dataQueue;
    std::condition_variable dataCond;
};

class FunctionWrapper
{
public:
    template <typename F>
    FunctionWrapper(F&& f) : impl(new ImplType<F>(std::move(f))) {}
    FunctionWrapper() = default;
    // only move semantics are supported
    FunctionWrapper(FunctionWrapper&& other);
    FunctionWrapper& operator=(FunctionWrapper&& other);
    // 'call' the FunctionWrapper
    void operator()() { impl->call(); }
    // copying not allowed
    FunctionWrapper(const FunctionWrapper&) = delete;
    FunctionWrapper(FunctionWrapper&) = delete;
    FunctionWrapper& operator=(const FunctionWrapper&) = delete;
private:
    // type erasure pattern to make call() typeless
    struct ImplBase
    {
        virtual ~ImplBase() {}
        virtual void call() = 0;
    };
    template <typename F> struct ImplType : ImplBase
    {
        ImplType(F&& f) : f(std::move(f)) {}
        virtual void call() override { f(); }
        F f;
    };
    std::unique_ptr<ImplBase> impl;
};

class JoinThreads
{
public:
    explicit JoinThreads(std::vector<std::thread>& threads) : threads(threads) {}
    ~JoinThreads();
private:
    std::vector<std::thread>& threads;
};

class ThreadPool
{
public:
    ThreadPool(int threadCount = -1);
    ~ThreadPool();
    template <typename FunctionType>
    std::future<typename std::result_of<FunctionType()>::type> submit(FunctionType f)
    {
        typedef typename std::result_of<FunctionType()>::type ResultType;
        std::packaged_task<ResultType()> task(std::move(f));
        std::future<ResultType> result(task.get_future());
        workQueue.push(std::move(task));
        return result;
    }
private:
    void workerThread();
    std::atomic_bool done;
    ThreadSafeQueue<FunctionWrapper> workQueue;
    std::vector<std::thread> threads;
    JoinThreads joinThreads;
};

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_THREADPOOL_H_ */
