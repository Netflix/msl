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
#include <Macros.h>
#include <MslEntityAuthException.h>
#include <MslError.h>

using namespace std;

namespace netflix {
namespace msl {

class MslEntityAuthExceptionTest : public ::testing::Test
{
};

TEST_F(MslEntityAuthExceptionTest, Constructors)
{
    // MslEntityAuthException from MslError
    const MslEntityAuthException meaex1(MslError::ENTITYAUTH_SIGNATURE_INVALID);
    EXPECT_EQ(MslError::ENTITYAUTH_SIGNATURE_INVALID, meaex1.getError());
    EXPECT_EQ(0ll, meaex1.getMessageId());
    EXPECT_EQ(NULL, meaex1.getCause().get());
    EXPECT_EQ(1u, meaex1.getDepth());
    EXPECT_EQ(string("Invalid entity authentication data signature."), meaex1.what());

    // MslEntityAuthException from MslError and details string
    const MslEntityAuthException meaex2(MslError::ENTITYAUTH_FACTORY_NOT_FOUND, "meaex2");
    EXPECT_EQ(MslError::ENTITYAUTH_FACTORY_NOT_FOUND, meaex2.getError());
    EXPECT_EQ(0ll, meaex2.getMessageId());
    EXPECT_EQ(NULL, meaex2.getCause().get());
    EXPECT_EQ(1u, meaex2.getDepth());
    EXPECT_EQ(string("No factory registered for entity authentication scheme. [meaex2]"), meaex2.what());

    // MslEntityAuthException from MslError, details string, and Exception cause
    const Exception cause3("cause3");
    const MslEntityAuthException meaex3(MslError::ENTITYAUTH_CIPHERTEXT_INVALID, "meaex3", cause3);
    EXPECT_EQ(MslError::ENTITYAUTH_CIPHERTEXT_INVALID, meaex3.getError());
    EXPECT_EQ(0ll, meaex3.getMessageId());
    EXPECT_EQ(2u, meaex3.getDepth());
    EXPECT_EQ(string("Invalid entity authentication data ciphertext. [meaex3]"), meaex3.what());
    shared_ptr<IException> exCause3 = meaex3.getCause();
    EXPECT_NE(shared_ptr<IException>(), exCause3);
    EXPECT_TRUE(instanceof<Exception>(exCause3.get()));
    EXPECT_EQ(string("cause3"), exCause3->what());

    // MslEntityAuthException from MslError, and Exception cause
    const Exception cause4("cause4");
    const MslEntityAuthException meaex4(MslError::ENTITYAUTH_VERIFICATION_FAILED, cause4);
    EXPECT_EQ(MslError::ENTITYAUTH_VERIFICATION_FAILED, meaex4.getError());
    EXPECT_EQ(0ll, meaex4.getMessageId());
    EXPECT_EQ(2u, meaex4.getDepth());
    EXPECT_EQ(string("Entity authentication data signature verification failed."), meaex4.what());
    shared_ptr<IException> exCause4 = meaex4.getCause();
    EXPECT_NE(shared_ptr<IException>(), exCause4);
    EXPECT_TRUE(instanceof<Exception>(exCause4.get()));
    EXPECT_EQ(string("cause4"), exCause4->what());

    // FIXME TODO
    //    MslEntityAuthException setMasterToken(const MasterToken& masterToken)

    // FIXME TODO
    //    MslEntityAuthException setEntityAuthenticationData(const EntityAuthenticationData& entityAuthData)
}

TEST_F(MslEntityAuthExceptionTest, Clone)
{
    MslEntityAuthException meaex1(MslError::ENTITYAUTH_SIGNATURE_INVALID);
    shared_ptr<IException> meaex1Clone = meaex1.clone();
    EXPECT_TRUE(instanceof<MslEntityAuthException>(meaex1Clone.get()));
}


}} // namespace netflix::msl
