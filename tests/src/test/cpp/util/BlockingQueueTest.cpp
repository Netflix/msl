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
#include <util/BlockingQueue.h>
#include <crypto/Random.h>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

// FIXME: These tests are a bit of an ad hoc mess and could use cleanup.

// BlockingQueue uses C++11, so C++11 is used here as well

using namespace std;
using namespace netflix::msl::crypto;

namespace netflix {
namespace msl {
namespace util {

namespace {

const int64_t TIMEOUTMS = 1000;

class Producer
{
public:
    Producer(BlockingQueue<int>& queue) : queue(queue) {}
    void deliver(vector<int> items) {
        for (auto i : items) {
            //cout << "producer " << this_thread::get_id() << ": " << i << '\n';
            queue.add(make_shared<int>(i));
            std::this_thread::sleep_for(std::chrono::nanoseconds(random.nextInt(100)));
        }
    }
private:
    Producer() = delete;
    Producer(const Producer&) = delete;
    Producer& operator=(const Producer&) = delete;
    BlockingQueue<int>& queue;
    Random random;
};

const int POISON = -1;

class Consumer
{
public:
    explicit Consumer(BlockingQueue<int>& queue) : queue(queue), isRunning(true), isFinished(false) {}
    void run() {
        shared_ptr<int> item;
        while (isRunning) {
            item = queue.poll(TIMEOUTMS);
            if (item) {
                lock_guard<mutex> lock(mut);
                //cout << "consumer " << this_thread::get_id() << ": " << *item << '\n';
                items.push_back(*item);
                if (*item == POISON)
                    break;
                std::this_thread::sleep_for(std::chrono::nanoseconds(random.nextInt(100)));
            }
        }
        isFinished = true;
    }
    void stop() {
        setNotRunning();
        queue.cancel();
    }
    void setNotRunning() { isRunning = false; }
    vector<int> getItems() {
        vector<int> tmp;
        lock_guard <mutex> lock(mut);
        tmp.swap(items);
        return tmp;
    }
    bool finished() { return isFinished; }
private:
    Consumer() = delete;
    Consumer(const Consumer&) = delete;
    Consumer& operator=(const Consumer&) = delete;
    BlockingQueue<int>& queue;
    vector<int> items;
    mutex mut;
    bool isRunning;
    Random random;
    bool isFinished;
};

vector<int> getItems(int length, bool poison=true) {
    vector<int> items;
    for (int i = 0; i < length; ++i)
        items.push_back(i);
    if (poison)
        items.push_back(POISON);
    return items;
}

} // namespace anonymous

class BlockingQueueTest : public ::testing::Test
{
protected:
    BlockingQueue<int> queue;
};

TEST_F(BlockingQueueTest, pollAndAdd)
{
    const vector<int> items = getItems(100);
    Consumer consumer(queue);
    Producer producer(queue);

    thread consumerThread(&Consumer::run, &consumer);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    thread producerThread(&Producer::deliver, &producer, items);

    producerThread.join();
    consumerThread.join();

    EXPECT_EQ(items, consumer.getItems());
}

TEST_F(BlockingQueueTest, addAndPoll)
{
    const vector<int> items = getItems(100);
    Producer producer(queue);
    Consumer consumer(queue);

    thread producerThread(&Producer::deliver, &producer, items);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    thread consumerThread(&Consumer::run, &consumer);

    consumerThread.join();
    producerThread.join();

    EXPECT_EQ(items, consumer.getItems());
}

TEST_F(BlockingQueueTest, pollTmeout)
{
    const int64_t timeoutms = 100;
    auto start = chrono::steady_clock::now();
    shared_ptr<int> result = queue.poll(timeoutms);
    auto end = chrono::steady_clock::now();
    const int64_t diff = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    EXPECT_TRUE(diff > timeoutms-10 && diff < timeoutms+10);
    EXPECT_FALSE(result);
}

TEST_F(BlockingQueueTest, cancel)
{
    Consumer consumer(queue);
    thread consumerThread(&Consumer::run, &consumer);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    EXPECT_FALSE(consumer.finished());
    consumer.setNotRunning();
    queue.cancel();
    consumerThread.join();
    EXPECT_TRUE(consumer.finished());
}

TEST_F(BlockingQueueTest, manyWriters)
{
    const size_t NITEMS = 100;
    const size_t NTHREADS = 100;

    // spawn many producers
    const vector<int> items = getItems(NITEMS, false); // no poison added
    vector<thread> threads;
    Producer producer(queue);
    for (size_t i=0; i < NTHREADS; ++i)
        threads.push_back(thread(&Producer::deliver, &producer, items));

    // spawn a single consumer
    Consumer consumer(queue);
    thread consumerThread(&Consumer::run, &consumer);

    // wait for the producers to finish
    for (size_t i=0; i < NTHREADS; ++i) threads[i].join();

    // kill the consumer and wait for it to finish
    queue.add(make_shared<int>(POISON)); // sentinel to make the consumer die
    consumerThread.join();

    // check all items sent through the queue are accounted for
    vector<int> consumedItems = consumer.getItems();;
    // drop the sentinel entry
    consumedItems.pop_back();
    // the total number of consumed items must be NITEMS*NTHREADS
    EXPECT_EQ(NITEMS*NTHREADS, consumedItems.size());
    // the number of unique items consumed must be NITEMS
    sort(consumedItems.begin(), consumedItems.end());
    size_t nUniq = 0;
    for (auto it = consumedItems.cbegin(), last = consumedItems.cend(); it != last; ++nUniq)
        it = std::upper_bound(it, last, *it);
    EXPECT_EQ(NITEMS, nUniq);
    // the unique consumed items must be identical to the original items vector
    auto it = unique(consumedItems.begin(), consumedItems.end());
    consumedItems.resize(static_cast<size_t>(std::distance(consumedItems.begin(), it)));
    EXPECT_EQ(items, consumedItems);
}

}}} // namespace netflix::msl::util
