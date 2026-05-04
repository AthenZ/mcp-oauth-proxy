/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.athenz.mop.service;

/**
 * Thrown by {@link SplunkManagementClient} write operations (createUser, updateUserRoles,
 * mintToken) when Splunk responds with a non-2xx status or the request fails in transport.
 *
 * <p>The {@code upstreamMessage} is the parsed first non-blank {@code messages[].text} from
 * the Splunk error body (see {@link SplunkManagementClientImpl#parseSplunkMessage}); when
 * Splunk returns a non-JSON body or no usable text, the raw body is preserved verbatim so
 * the caller can still surface the cause.</p>
 *
 * <p>{@link #getMessage()} renders {@code "Splunk <operation> failed: status=<n>, message=<text>"}
 * — designed to drop straight into a 401 {@code error_description} without further reformatting.
 * {@code status=0} is used for transport errors (interrupt, IOException) where there is no HTTP
 * status to report.</p>
 */
public class SplunkApiException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final int status;
    private final String operation;
    private final String upstreamMessage;

    public SplunkApiException(int status, String operation, String upstreamMessage) {
        super(render(status, operation, upstreamMessage));
        this.status = status;
        this.operation = operation;
        this.upstreamMessage = upstreamMessage;
    }

    public int status() {
        return status;
    }

    public String operation() {
        return operation;
    }

    public String upstreamMessage() {
        return upstreamMessage;
    }

    private static String render(int status, String operation, String upstreamMessage) {
        return "Splunk " + operation + " failed: status=" + status + ", message=" + upstreamMessage;
    }
}
