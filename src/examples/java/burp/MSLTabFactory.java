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
package burp;

/**
 * User: skommidi
 * Date: 9/25/14
 */
public class MSLTabFactory implements IMessageEditorTabFactory {

    public MSLTabFactory(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        MSLTab mslTab = new MSLTab(controller, editable, callbacks, helpers);
        return mslTab;
    }

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
}
