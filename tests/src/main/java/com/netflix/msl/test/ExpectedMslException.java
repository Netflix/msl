/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.test;

import static org.hamcrest.CoreMatchers.both;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;

import org.hamcrest.Matcher;
import org.hamcrest.StringDescription;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Assert;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import com.netflix.msl.MslConstants.ResponseCode;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;

/**
 * <p>The {@code ExpectedMslException} rule allows in-test specification of
 * expected {@link MslException} types and internal error:
 * 
 * <pre>
 * // These tests all pass.
 * public static class HasExpectedMslException {
 *   &#064;Rule
 *   public ExpectedMslException thrown = ExpectedMslException.none();
 *   
 *   &#064;Test
 *   public void throwsNothing() {
 *     // no exception expected, none thrown: passes.
 *   }
 * 
 *   &#064;Test
 *   public void throwsMslException() {
 *     thrown.expect(MslMessageException.class);
 *     thrown.expectMslError(MslError.JSON_PARSE_ERROR);
 *     throw new MslMessageException(MslError.JSON_PARSE_ERROR);
 *   }
 * 
 *   &#064;Test
 *   public void throwsMslExceptionWithResponseCode() {
 *     thrown.expectResponseCode(ResponseCode.FAIL);
 *     throw new MslException(MslError.JSON_PARSE_ERROR);
 *   }
 * }
 * </pre>
 * </p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ExpectedMslException implements TestRule {
    /**
     * A statement expecting a {@code MslException}.
     */
    private class ExpectedMslExceptionStatement extends Statement {
        /**
         * Create a new statement expecting expecting a {@code MslException} if
         * the outer class has a matcher.
         * 
         * @param base the base statement.
         */
        public ExpectedMslExceptionStatement(final Statement base) {
            fNext = base;
        }
        
        /* (non-Javadoc)
         * @see org.junit.runners.model.Statement#evaluate()
         */
        @Override
        public void evaluate() throws Throwable {
            try {
                fNext.evaluate();
            } catch (final Throwable t) {
                if (fMatcher == null)
                    throw t;
                Assert.assertThat(t, fMatcher);
                return;
            }
            if (fMatcher != null)
                throw new AssertionError("Expected test to throw " + StringDescription.toString(fMatcher));
        }
        
        /** The base statement. */
        private final Statement fNext;
    }
    
    /**
     * Create a new {@code MslException} matcher that expects a specific MSL
     * error.
     * 
     * @param error the expected MSL error.
     * @return the matcher.
     */
    private Matcher<MslException> hasMslError(final MslError error) {
        return new TypeSafeMatcher<MslException>() {
            @Override
            public void describeTo(final org.hamcrest.Description description) {
                description.appendText("MslException with internal code ");
                description.appendDescriptionOf(equalTo(error.getInternalCode()));
            }

            @Override
            protected boolean matchesSafely(final MslException item) {
                return is(error).matches(item.getError());
            }
        };
    }
    
    /**
     * Create a new {@code MslException} matcher that expects a specific
     * response code.
     * 
     * @param code the expected response code.
     * @return the matcher.
     */
    private Matcher<MslException> hasResponseCode(final ResponseCode code) {
        return new TypeSafeMatcher<MslException>() {
            @Override
            public void describeTo(final org.hamcrest.Description description) {
                description.appendText("MslException with response code ");
                description.appendDescriptionOf(equalTo(code));
            }

            @Override
            protected boolean matchesSafely(final MslException item) {
                return is(code).matches(item.getError().getResponseCode());
            }
        };
    }
    
    /**
     * Create a new {@code MslException} matcher that expects a specific
     * message ID.
     * 
     * @param id the expected message ID.
     * @return the matcher.
     */
    private Matcher<MslException> hasMessageId(final long id) {
        return new TypeSafeMatcher<MslException>() {
            @Override
            public void describeTo(final org.hamcrest.Description description) {
                description.appendText("MslException with message ID ");
                description.appendDescriptionOf(equalTo(id));
            }

            @Override
            protected boolean matchesSafely(final MslException item) {
                return is(id).matches(item.getMessageId());
            }
        };
    }
    
    /**
     * @return a rule that expects no MslException to be thrown (identical to
     *         behavior without this rule).
     */
    public static ExpectedMslException none() {
        return new ExpectedMslException();
    }

    /**
     * Adds {@code matcher} to the list of requirements for any thrown
     * exception.
     */
    // Should be able to remove this suppression in some brave new hamcrest world.
    @SuppressWarnings("unchecked")
    public void expect(final Matcher<?> matcher) {
        if (fMatcher == null)
            fMatcher = (Matcher<Object>)matcher;
        else
            fMatcher = both(fMatcher).and((Matcher<? super Object>)matcher);
    }
    
    /**
     * Adds to the list of requirements for any thrown exception that it should
     * be an instance of {@code type}.
     * 
     * @param type the specific Exception type.
     */
    public void expect(final Class<? extends Exception> type) {
        expect(instanceOf(type));
    }
    
    /**
     * Adds to the list of requirements for any thrown exception that it should
     * be a {@code MslException} with the specified {@code MslError}.
     * 
     * @param error the specific MSL error.
     */
    public void expectMslError(final MslError error) {
        expect(hasMslError(error));
    }
    
    /**
     * Adds to the list of requirements for any thrown exception that it should
     * be a {@code MslException} with the specified {@code ResponseCode}.
     * 
     * @param code the specific response code.
     */
    public void expectResponseCode(final ResponseCode code) {
        expect(hasResponseCode(code));
    }
    
    /**
     * Adds to the list of requirements for any thrown exception that it should
     * be a {@code MslException} with the specified message ID.
     * 
     * @param id the specific message ID.
     */
    public void expectMessageId(final long id) {
        expect(hasMessageId(id));
    }
    
    /* (non-Javadoc)
     * @see org.junit.rules.TestRule#apply(org.junit.runners.model.Statement, org.junit.runner.Description)
     */
    @Override
    public Statement apply(final Statement base, final Description description) {
        return new ExpectedMslExceptionStatement(base);
    }
    
    /** Rule requirements. */
    private Matcher<Object> fMatcher = null;
}
