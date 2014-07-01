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
 * <p>Thrown when an exception occurs while attempting to create and send an
 * automatically generated error response.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslErrorResponseException extends Exception {
    private static final long serialVersionUID = 3844789699705189994L;

    /**
     * <p>Construct a new MSL error response exception with the specified detail
     * message, cause, and the original exception thrown by the request that
     * prompted an automatic error response.</p>
     * 
     * <p>The detail message should describe the error that triggered the
     * automatically generated error response.</p>
     * 
     * @param message the detail message.
     * @param cause the cause.
     * @param requestCause the original request exception.
     */
    public MslErrorResponseException(final String message, final Throwable cause, final Throwable requestCause) {
        super(message, cause);
        this.requestCause = requestCause;
    }
    
    /**
     * @return the exception thrown by the request that prompted the error
     *         response.
     */
    public Throwable getRequestCause() {
        return requestCause;
    }
    
    /** The original exception thrown by the request. */
    private final Throwable requestCause;
}
