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
package burp.msl.msg;

import com.netflix.msl.msg.Header;
import com.netflix.msl.msg.MessageDebugContext;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * <p>Capture sent and received MSL (message and error) headers.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class CaptureMessageDebugContext implements MessageDebugContext {
    /**
     * <p>Create a new capture message debug context that will capture sent
     * and/or received headers.</p>
     * 
     * @param captureSent capture sent headers.
     * @param captureReceived capture received headers.
     */
    public CaptureMessageDebugContext(final boolean captureSent, final boolean captureReceived) {
        this.captureSent = captureSent;
        this.captureReceived = captureReceived;
    }
    

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageDebugContext#sentHeader(com.netflix.msl.msg.Header)
     */
    @Override
    public void sentHeader(final Header header) {
        if (captureSent)
            sent.add(header);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.msg.MessageDebugContext#receivedHeader(com.netflix.msl.msg.Header)
     */
    @Override
    public void receivedHeader(final Header header) {
        if (captureReceived)
            received.add(header);
    }
    
    /**
     * @return the sent headers, in order.
     */
    public List<Header> getSentHeaders() {
        return Collections.unmodifiableList(sent);
    }
    
    /**
     * @return the received headers, in order.
     */
    public List<Header> getReceivedHeaders() {
        return Collections.unmodifiableList(received);
    }

    /** Capture sent headers. */
    private final boolean captureSent;
    /** Capture received headers. */
    private final boolean captureReceived;
    
    /** Sent headers. */
    private final List<Header> sent = new ArrayList<Header>();
    /** Received headers. */
    private final List<Header> received = new ArrayList<Header>();
}
