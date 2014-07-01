/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl;

/**
 * Thrown when an exception occurs that should not happen except due to an
 * internal error (e.g. incorrectly written code).
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslInternalException extends RuntimeException {
    private static final long serialVersionUID = 5787827728910061805L;

    /**
     * Construct a new MSL internal exception with the specified detail
     * message and cause.
     * 
     * @param message the detail message.
     * @param cause the cause.
     */
    public MslInternalException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Construct a new MSL internal exception with the specified detail
     * message.
     * 
     * @param message the detail message.
     */
    public MslInternalException(final String message) {
        super(message);
    }
}
