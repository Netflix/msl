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
package kancolle.entityauth;

/**
 * A naval port's secret code book used to authentication.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface CodeBook {
    /**
     * @return the number of pages in the code book.
     */
    public int getPageCount();

    /**
     * @param page the page number, 1-based.
     * @return the number of words on the given page.
     * @throws IllegalArgumentException if the page number is invalid.
     */
    public int getWordCount(int page) throws IllegalArgumentException;

    /**
     * Returns the word located at the specified page and word.
     * 
     * @param page the page number, 1-based.
     * @param word the word number, 1-based.
     * @return the specified word.
     * @throws IllegalArgumentException if the page and word number combination
     *         is invalid.
     */
    public String getWord(int page, int word) throws IllegalArgumentException;
}