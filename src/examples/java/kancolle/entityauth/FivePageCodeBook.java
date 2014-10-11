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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

/**
 * <p>A code book that considers one page to consist of five lines of text.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class FivePageCodeBook implements CodeBook {
    /** Five lines per page. */
    private static final int LINES_PER_PAGE = 5;
    
    /**
     * <p>Create a new code book from the given input stream.</p>
     * 
     * @param in code book input stream.
     * @throws IOException if there is an error reading the code book.
     */
    public FivePageCodeBook(final InputStream in) throws IOException {
        // Convert the raw bytes to a string.
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final byte[] b = new byte[4096];
        do {
            final int read = in.read(b);
            if (read == -1) break;
            baos.write(b, 0, read);
        } while (true);
        final String text = baos.toString();
        
        // Add words to the page until we hit the fifth newline.
        final StringTokenizer tokenizer = new StringTokenizer(text, " \t\n\r\f", true);
        List<String> page = new ArrayList<String>();
        int lineNumber = 1;
        while (tokenizer.hasMoreTokens()) {
            final String token = tokenizer.nextToken();
            
            // Skip spaces, tabs, and form feeds.
            if (" \t\f".indexOf(token) != -1)
                continue;
            
            // On newlines, add the current page (if not empty) and move
            // forward.
            if ("\n\r".indexOf(token) != -1) {
                ++lineNumber;
                if (lineNumber % LINES_PER_PAGE == 0 && page.size() > 0) {
                    pages_words.add(page);
                    page = new ArrayList<String>();
                }
                continue;
            }
            
            // Add word.
            page.add(token);
        }
        
        // Add the final page (if not empty).
        if (page.size() > 0)
            pages_words.add(page);
    }
    

    /* (non-Javadoc)
     * @see kancolle.entityauth.CodeBook#getPageCount()
     */
    @Override
    public int getPageCount() {
        return pages_words.size();
    }

    /* (non-Javadoc)
     * @see kancolle.entityauth.CodeBook#getWordCount(int)
     */
    @Override
    public int getWordCount(final int page) {
        if (page > pages_words.size())
            throw new IllegalArgumentException("The page number " + page + " exceeds the code book page count.");
        final List<String> words = pages_words.get(page - 1);
        return words.size();
    }

    /* (non-Javadoc)
     * @see kancolle.entityauth.CodeBook#getWord(int, int)
     */
    @Override
    public String getWord(final int page, final int word) {
        if (page > pages_words.size())
            throw new IllegalArgumentException("The page number " + page + " exceeds the code book page count.");
        final List<String> words = pages_words.get(page - 1);
        if (word > words.size())
            throw new IllegalArgumentException("The word number " + word + " exceeds the code book word count on page " + page + ".");
        return words.get(word - 1);
    }

    /** Pages and words. */
    private final List<List<String>> pages_words = new ArrayList<List<String>>();
}
