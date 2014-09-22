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
 * <p>Issue orders.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class OrderResponseMessageContext extends KanColleMessageContext {
    /**
     * <p>Create a new issued orders response message with the provided
     * orders.</p>
     * 
     * @param orders the orders.
     */
    public OrderResponseMessageContext(final String orders) {
        super(null, null, null);
        this.orders = orders;
    }

    @Override
    public boolean isNonReplayable() {
        return true;
    }
    
    @Override
    public void write(final MessageOutputStream output) throws IOException {
        MessageProcessor.issueOrders(output, orders);
    }
    
    /** Orders. */
    private final String orders;
}
