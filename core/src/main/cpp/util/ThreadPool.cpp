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

#include <assert.h>
#include <util/ThreadPool.h>
#include <iomanip>
#include <iostream>
#include <thread>

//#define DEBUG
#include <util/Debug.h>

using namespace std;

namespace netflix {
namespace msl {
namespace util {

namespace {
Debug myCout(cout);
}


JoinThreads::~JoinThreads()
{
    for (size_t i=0; i<threads.size(); ++i) {
        if (threads[i].joinable()) {
            myCout << "thread " << hex << threads[i].get_id() << dec << " joined\n";
            threads[i].join();
        }
    }
}

FunctionWrapper::FunctionWrapper(FunctionWrapper&& other) : impl(move(other.impl))
{
}

FunctionWrapper& FunctionWrapper::operator=(FunctionWrapper&& other)
{
    impl = move(other.impl);
    return *this;
}

ThreadPool::ThreadPool(int threadCount) : done(false), joinThreads(threads)
{
    assert(threadCount != 0); // for now
    if (threadCount < 0)
        threadCount = static_cast<int>(thread::hardware_concurrency());
    myCout << "ThreadPool ctor: starting " << threadCount << " threads\n";
    try {
        for (int i=0; i<threadCount; ++i) {
            threads.push_back(thread(&ThreadPool::workerThread, this));
        }
    } catch (...) {
        done = true;
        throw;
    }
}

ThreadPool::~ThreadPool()
{
    myCout << "ThreadPool dtor: stopping threads\n";
    done = true;
}

void ThreadPool::workerThread()
{
    myCout << "thread " << hex << this_thread::get_id() << dec << " started\n";
    while (!done)
    {
        FunctionWrapper task;
        if (workQueue.tryPop(task)) {
            myCout << "thread " << hex << this_thread::get_id() << dec << " found task on queue, running now\n";
            task();
            myCout << "thread " << hex << this_thread::get_id() << dec << " task complete\n";
        }
        else
            this_thread::yield();
    }
    myCout << "thread " << hex << this_thread::get_id() << dec << " done\n";
}

}}} // namespace netflix::msl::util
