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
 * <p>Pings are periodically sent from Kanmusu to naval ports.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class PingMessageContext extends KanColleMessageContext {
    /**
     * <p>Create a new ping message context.</p>
     */
    public PingMessageContext() {
        super(null, null, null);
    }

    @Override
    public boolean isEncrypted() {
        return false;
    }
    
    @Override
    public void write(final MessageOutputStream output) throws IOException {
        MessageProcessor.ping(output);
    }
}
