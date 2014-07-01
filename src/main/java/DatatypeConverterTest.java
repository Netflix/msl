import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import com.netflix.msl.util.JsonUtils;

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

/**
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class DatatypeConverterTest {
    @Test
    public void urlEncodeDtDecode() {
        final String s = "test string";
        final String urlEncoded = JsonUtils.b64urlEncode(s.getBytes());
        final byte[] decoded = DatatypeConverter.parseBase64Binary(urlEncoded);
        final String sr = new String(decoded);
        System.err.println("s: " + s);
        System.err.println("urlEncoded: " + urlEncoded);
        System.err.println("sr: " + sr);
    }
}
