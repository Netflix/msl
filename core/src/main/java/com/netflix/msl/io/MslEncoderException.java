/**
 * Copyright (c) 2015-2017 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.io;

/**
 * <p>A MSL encoder exception is thrown by the MSL encoding abstraction classes
 * when there is a problem.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslEncoderException extends Exception {
    private static final long serialVersionUID = -6338714624096298489L;

    /**
     * <p>Construct a new MSL encoder exception with the provided message.</p>
     * 
     * @param message the detail message.
     */
    public MslEncoderException(final String message) {
        super(message);
    }
    
    /**
     * <p>Construct a new MSL encoder exception with the provided cause.</p>
     * 
     * @param cause the cause of the exception.
     */
    public MslEncoderException(final Throwable cause) {
        super(cause);
    }
    
    /**
     * <p>Construct a new MSL encoder exception with the provided message and
     * cause.</p>
     * 
     * @param message the detail message.
     * @param cause the cause of the exception.
     */
    public MslEncoderException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
