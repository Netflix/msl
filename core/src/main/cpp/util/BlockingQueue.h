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

#ifndef SRC_UTIL_BLOCKINGQUEUE_H_
#define SRC_UTIL_BLOCKINGQUEUE_H_

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>

namespace netflix {
namespace msl {
namespace util {

// Thread-safe queue of shared_ptr's to T, to support a consumer-producer thread
// model. This class is intended to model java's BlockingQueue, but only in the
// strict way it is used by MslControl.
// This class requires C++11.
template <typename T>
class BlockingQueue
{
public:
    BlockingQueue() : isCancelled(false) {}
    ~BlockingQueue() { cancel(); }
    void add(std::shared_ptr<T> newValue)
    {
        std::lock_guard<std::mutex> lock(mutex);
        dataQueue.push(std::move(newValue));
        dataCond.notify_one();
    }
    std::shared_ptr<T> poll(int64_t timeoutMs)
    {
        const std::chrono::milliseconds timeout(timeoutMs);
        std::unique_lock<std::mutex> lock(mutex);
        dataCond.wait_for(lock, timeout, [this] {return !dataQueue.empty() || isCancelled;});
        if (dataQueue.empty() || isCancelled) { // a timeout or cancel occurred
            isCancelled = false;
            return std::shared_ptr<T>();
        }
        std::shared_ptr<T> value = dataQueue.front();
        dataQueue.pop();
        return value;
    }
    void cancel()
    {
        std::lock_guard<std::mutex> lock(mutex);
        isCancelled = true;
        std::queue<std::shared_ptr<T>>().swap(dataQueue); // clear dataQueue
        dataCond.notify_all();
    }
private:
    mutable std::mutex mutex;
    std::queue<std::shared_ptr<T>> dataQueue;
    std::condition_variable dataCond;
    bool isCancelled;
};

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_BLOCKINGQUEUE_H_ */
