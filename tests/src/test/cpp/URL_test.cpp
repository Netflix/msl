/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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
#include <Url.h>

using namespace std;
using namespace netflix::msl;

class URLTest : public ::testing::Test
{
};

TEST_F(URLTest, componentsFull)
{
    string testurlstring = "https://jdoe:opensesame@subdomain.example.com:4443/path/to/nowhere?arg1=value1&arg2=value2#fragment";
    Url urlToTest = Url(testurlstring);
    string teststring;
    
    teststring = urlToTest.getAuthority();
    EXPECT_EQ(teststring, "jdoe:opensesame@subdomain.example.com:4443");

    teststring = urlToTest.getFile();
    EXPECT_EQ(teststring, "nowhere");

    teststring = urlToTest.getHost();
    EXPECT_EQ(teststring, "subdomain.example.com");
    
    int testport = urlToTest.getPort();
    EXPECT_EQ(testport, 4443);
    
    teststring = urlToTest.getPath();
    EXPECT_EQ(teststring, "/path/to/nowhere");
    
    teststring = urlToTest.getProtocol();
    EXPECT_EQ(teststring, "https");

    teststring = urlToTest.getQuery();
    EXPECT_EQ(teststring, "?arg1=value1&arg2=value2");

    teststring = urlToTest.getRef();
    EXPECT_EQ(teststring, "#fragment");
    
    teststring = urlToTest.getUserInfo();
    EXPECT_EQ(teststring, "jdoe:opensesame");

    teststring = urlToTest.toString();
    EXPECT_EQ(teststring, testurlstring);
}

TEST_F(URLTest, componentsFew)
{
    string testurlstring = "https://example.com/index.html";
    Url urlToTest = Url(testurlstring);
    string teststring;
    
    teststring = urlToTest.getAuthority();
    EXPECT_EQ(teststring, "example.com");
    
    teststring = urlToTest.getFile();
    EXPECT_EQ(teststring, "index.html");
    
    teststring = urlToTest.getHost();
    EXPECT_EQ(teststring, "example.com");
    
    int testport = urlToTest.getPort();
    EXPECT_EQ(testport, 0);
    
    teststring = urlToTest.getPath();
    EXPECT_EQ(teststring, "/index.html");
    
    teststring = urlToTest.getProtocol();
    EXPECT_EQ(teststring, "https");
    
    teststring = urlToTest.getQuery();
    EXPECT_EQ(teststring, "");
    
    teststring = urlToTest.getRef();
    EXPECT_EQ(teststring, "");
    
    teststring = urlToTest.getUserInfo();
    EXPECT_EQ(teststring, "");
    
    teststring = urlToTest.toString();
    EXPECT_EQ(teststring, testurlstring);
}

TEST_F(URLTest, componentsSome)
{
    string testurlstring = "https://subdomain.example.com:4443/path/to/nowhere#fragment";
    Url urlToTest = Url(testurlstring);
    string teststring;
    
    teststring = urlToTest.getAuthority();
    EXPECT_EQ(teststring, "subdomain.example.com:4443");
    
    teststring = urlToTest.getFile();
    EXPECT_EQ(teststring, "nowhere");
    
    teststring = urlToTest.getHost();
    EXPECT_EQ(teststring, "subdomain.example.com");
    
    int testport = urlToTest.getPort();
    EXPECT_EQ(testport, 4443);
    
    teststring = urlToTest.getPath();
    EXPECT_EQ(teststring, "/path/to/nowhere");
    
    teststring = urlToTest.getProtocol();
    EXPECT_EQ(teststring, "https");
    
    teststring = urlToTest.getQuery();
    EXPECT_EQ(teststring, "");
    
    teststring = urlToTest.getRef();
    EXPECT_EQ(teststring, "#fragment");
    
    teststring = urlToTest.getUserInfo();
    EXPECT_EQ(teststring, "");
    
    teststring = urlToTest.toString();
    EXPECT_EQ(teststring, testurlstring);
}

TEST_F(URLTest, comparisons)
{
    string testurlstring1 = "https://subdomain.example.com:4443/path/to/nowhere#fragment";
    Url urlToTest1 = Url(testurlstring1);
    
    string testurlstring2 = "https://example.com/index.html";
    Url urlToTest2 = Url(testurlstring2);
    
    EXPECT_TRUE(urlToTest1 == urlToTest1);
    EXPECT_TRUE(urlToTest1 != urlToTest2);
    EXPECT_TRUE(urlToTest1 >  urlToTest2);
    EXPECT_TRUE(urlToTest1 >= urlToTest2);
    EXPECT_TRUE(urlToTest2 <  urlToTest1);
    EXPECT_TRUE(urlToTest2 <= urlToTest1);
    
    EXPECT_FALSE(urlToTest1 == urlToTest2);
    EXPECT_FALSE(urlToTest1 != urlToTest1);
    EXPECT_FALSE(urlToTest2 >  urlToTest1);
    EXPECT_FALSE(urlToTest2 >= urlToTest1);
    EXPECT_FALSE(urlToTest1 <  urlToTest2);
    EXPECT_FALSE(urlToTest1 <= urlToTest2);
}

#if 0
TEST_F(URLTest, io)
{
    string testurlstring1 = "https://subdomain.example.com:4443/path/to/nowhere#fragment";
    Url urlToTest1 = Url(testurlstring1);
    
    stringstream ss;
    ss << urlToTest1;
    
    EXPECT_EQ(ss.str(), urlToTest1.toString());
}
#endif




