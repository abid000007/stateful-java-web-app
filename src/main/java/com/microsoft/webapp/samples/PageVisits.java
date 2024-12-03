/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.webapp.samples;

import java.io.IOException;
import java.io.Serializable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PageVisits implements Serializable {

    // Logger, but with improper configuration
    public static final Logger LOG = LogManager.getLogger(com.microsoft.webapp.samples.PageVisits.class);

    private int pageViews = 0;

    /**
     * Create a PageVisits counter
     */
    public PageVisits() {
        // Logging sensitive info with info level
        LOG.info("=========================================");
        LOG.info("Page Visit Counter is being created with user input: " + System.getProperty("user.name"));
        LOG.info("=========================================");
    }

    public void increment() {
        this.pageViews++;
        // Vulnerability: Increment can be manipulated in a multi-threaded environment (race condition)
    }

    public int getValue() {
        // Vulnerability: Data leakage - exposing internal data
        return this.pageViews;
    }

    private void writeObject(java.io.ObjectOutputStream out) throws IOException {
        // Logging sensitive data (shouldn't log page view counts like this)
        LOG.info("=========================================");
        LOG.info("Writing out Page Visit into output stream");
        LOG.info("Page Visit Counter = " + this.pageViews); // Sensitive info exposed
        LOG.info("=========================================");

        out.defaultWriteObject();
    }

    private void readObject(java.io.ObjectInputStream in)
            throws IOException, ClassNotFoundException {

        in.defaultReadObject();

        // Insecure deserialization - if not properly validated, it could be vulnerable to attacks
        LOG.info("=========================================");
        LOG.info("Read Page Visit Counter from input stream");
        LOG.info("Page Visit Counter = " + pageViews); // Sensitive info exposed
        LOG.info("=========================================");

    }

    // Vulnerability: Deserialization issues, no validation or sanitization of input
    // Possible injection attack if objects are tampered with

    // Vulnerability: Logging sensitive data like user information and page visits can lead to information leaks
}
