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
#include <crypto/OpenSslLib.h>
#include <crypto/Random.h>
#include <MslConstants.h>
#include <MslInternalException.h>
#include <math.h>
#include <chrono>
#include <thread>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <iomanip>
#include <set>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::crypto;

namespace netflix {
namespace msl {
namespace crypto {

namespace {

// http://www.johndcook.com/blog/standard_deviation/
class RunningStat
{
public:
    RunningStat() : m_n(0), m_oldM(0.), m_newM(0.), m_oldS(0.), m_newS(0.) {}
    void clear() { m_n = 0; }
    void push(double x) {
        m_n++;
        // See Knuth TAOCP vol 2, 3rd edition, page 232
        if (m_n == 1) {
            m_oldM = m_newM = x;
            m_oldS = 0.0;
        } else {
            m_newM = m_oldM + (x - m_oldM)/m_n;
            m_newS = m_oldS + (x - m_oldM)*(x - m_newM);

            // set up for next iteration
            m_oldM = m_newM;
            m_oldS = m_newS;
        }
    }
    int numDataValues() const { return m_n; }
    double mean() const { return (m_n > 0) ? m_newM : 0.0; }
    double variance() const {
        return ( (m_n > 1) ? m_newS/(m_n - 1) : 0.0 );
    }
    double standardDeviation() const { return sqrt( variance() ); }
private:
    int m_n;
    double m_oldM, m_newM, m_oldS, m_newS;
};

}

class RandomTest : public ::testing::Test
{
public:
    RandomTest() : random(make_shared<Random>()) {}
protected:
    shared_ptr<IRandom> random;
};

// http://www.johndcook.com/Beautiful_Testing_ch10.pdf
TEST_F(RandomTest, nextIntStats)
{
    RunningStat rs;
    const int N = 1000000;
    for (int i=0; i<N; ++i)
        rs.push(random->nextInt());

    // The range of an int32_t is -2,147,483,648..2,147,483,648 with mean value
    // 0 if the values are uniformly distributed. For a uniform distribution
    // over range [min, max], the standard deviation of a single value is
    // (max-min)/√12 = 1239850261. For a set of N of such values, the standard
    // deviation is smaller than that of an individual sample by a factor of
    // 1/√N, or 1239850.
    EXPECT_NEAR(0., rs.mean(), 2.*1239850.);

    // For a normal distribution the sample variance is σ^2. Let S^2 be the
    // set variance based on N samples. If N is very large, then S^2
    // approximately has a normal distribution with mean σ^2 and variance
    // 2σ^4/(n−1).
    const double sigma2 = 1239850261.*1239850261.;
    EXPECT_NEAR(sigma2, rs.variance(), 2*sqrt(2.*sigma2*sigma2/(N-1)));
}

TEST_F(RandomTest, nextIntRange)
{
    const uint32_t rangeMax = static_cast<uint32_t>(abs(random->nextInt()));
    set<int32_t> values;
    const int NITERATIONS = 65536;
    for (int i=0; i<NITERATIONS; ++i)
        values.insert(random->nextInt(rangeMax));
    EXPECT_LE(0, *values.begin());
    EXPECT_GE(rangeMax-1, (unsigned)(*values.rbegin()));
}

TEST_F(RandomTest, nextLongRange)
{
    const uint64_t rangeMax = static_cast<uint64_t>(abs(random->nextLong()));
    set<int64_t> values;
    const int NITERATIONS = 65536;
    for (int i=0; i<NITERATIONS; ++i)
        values.insert(random->nextLong(rangeMax));
    EXPECT_LE(0, *values.begin());
    EXPECT_GE(rangeMax-1, (unsigned)(*values.rbegin()));
}

}}} // namespace netflix::msl::crypto
