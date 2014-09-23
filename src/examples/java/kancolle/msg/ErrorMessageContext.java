/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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
package kancolle.msg;

import java.io.IOException;

import com.netflix.msl.msg.MessageOutputStream;

/**
 * <p>An error message sent in response to failed requests.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ErrorMessageContext extends KanColleMessageContext {
    /**
     * <p>Create a new error message context.</p>
     * 
     * @param message the error message.
     */
    public ErrorMessageContext(final String message) {
        super(null, null, null);
        this.message = message;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageContext#write(com.netflix.msl.msg.MessageOutputStream)
     */
    @Override
    public void write(final MessageOutputStream output) throws IOException {
        MessageProcessor.error(output, message);
    }
    
    /** Error message. */
    private final String message;
}
