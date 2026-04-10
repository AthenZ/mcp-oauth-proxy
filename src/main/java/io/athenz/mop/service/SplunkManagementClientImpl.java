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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.athenz.mop.model.splunk.SplunkTokensFeedResponse;
import io.athenz.mop.model.splunk.SplunkUsersFeedResponse;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class SplunkManagementClientImpl implements SplunkManagementClient {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private final ObjectMapper objectMapper;
    private final SplunkHttpExecutor splunkHttpExecutor;

    @Inject
    public SplunkManagementClientImpl(ObjectMapper objectMapper, SplunkHttpExecutor splunkHttpExecutor) {
        this.objectMapper = objectMapper;
        this.splunkHttpExecutor = splunkHttpExecutor;
    }

    @Override
    public SplunkUserLookup getUser(String mgmtBaseUrl, String adminBearer, String username) {
        String base = normalizeBase(mgmtBaseUrl);
        if (base == null || StringUtils.isBlank(adminBearer) || StringUtils.isBlank(username)) {
            return new SplunkUserLookup(false, List.of());
        }
        try {
            String path = "/services/authentication/users/" + urlEncodePath(username) + "?output_mode=json";
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(base + path))
                    .header("Authorization", "Bearer " + adminBearer)
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            HttpResponse<String> resp = splunkHttpExecutor.send(req);
            if (resp.statusCode() == 404) {
                return new SplunkUserLookup(false, List.of());
            }
            if (resp.statusCode() != 200) {
                log.warn("Splunk getUser non-success: status={} user={}", resp.statusCode(), username);
                return new SplunkUserLookup(false, List.of());
            }
            SplunkUsersFeedResponse feed = objectMapper.readValue(resp.body(), SplunkUsersFeedResponse.class);
            if (feed.entry() == null || feed.entry().isEmpty()) {
                return new SplunkUserLookup(false, List.of());
            }
            var first = feed.entry().get(0);
            var content = first != null ? first.content() : null;
            List<String> roles = content != null && content.roles() != null ? content.roles() : List.of();
            return new SplunkUserLookup(true, roles);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Splunk getUser error: {}", e.getMessage());
            return new SplunkUserLookup(false, List.of());
        } catch (IOException e) {
            log.warn("Splunk getUser error: {}", e.getMessage());
            return new SplunkUserLookup(false, List.of());
        }
    }

    @Override
    public void createUser(String mgmtBaseUrl, String adminBearer, String username, String password, List<String> roles) {
        String base = normalizeBase(mgmtBaseUrl);
        if (base == null) {
            return;
        }
        String body = formEncodeUserCreate(username, password, roles);
        postForm(base + "/services/authentication/users?output_mode=json", adminBearer, body);
    }

    @Override
    public void updateUserRoles(String mgmtBaseUrl, String adminBearer, String username, List<String> roles) {
        String base = normalizeBase(mgmtBaseUrl);
        if (base == null) {
            return;
        }
        String body = formEncodeRolesOnly(roles);
        String path = "/services/authentication/users/" + urlEncodePath(username) + "?output_mode=json";
        postForm(base + path, adminBearer, body);
    }

    @Override
    public String mintToken(String mgmtBaseUrl, String adminBearer, String username, String audience, String expiresOn) {
        String base = normalizeBase(mgmtBaseUrl);
        if (base == null) {
            return null;
        }
        String body = "name=" + urlForm(username)
                + "&audience=" + urlForm(audience)
                + "&expires_on=" + urlForm(expiresOn);
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(base + "/services/authorization/tokens?output_mode=json"))
                    .header("Authorization", "Bearer " + adminBearer)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> resp = splunkHttpExecutor.send(req);
            if (resp.statusCode() != 200 && resp.statusCode() != 201) {
                log.warn("Splunk mintToken failed: status={}", resp.statusCode());
                return null;
            }
            SplunkTokensFeedResponse feed = objectMapper.readValue(resp.body(), SplunkTokensFeedResponse.class);
            if (feed.entry() == null || feed.entry().isEmpty()) {
                return null;
            }
            var first = feed.entry().get(0);
            var content = first != null ? first.content() : null;
            if (content == null || StringUtils.isBlank(content.token())) {
                return null;
            }
            return content.token();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Splunk mintToken error: {}", e.getMessage());
            return null;
        } catch (IOException e) {
            log.warn("Splunk mintToken error: {}", e.getMessage());
            return null;
        }
    }

    private void postForm(String url, String adminBearer, String body) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Authorization", "Bearer " + adminBearer)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> resp = splunkHttpExecutor.send(req);
            if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
                log.warn("Splunk POST failed: status={} url={}", resp.statusCode(), url);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Splunk POST error: {}", e.getMessage());
        } catch (IOException e) {
            log.warn("Splunk POST error: {}", e.getMessage());
        }
    }

    static String formEncodeUserCreate(String username, String password, List<String> roles) {
        StringBuilder sb = new StringBuilder();
        sb.append("name=").append(urlForm(username));
        sb.append("&password=").append(urlForm(password));
        for (String r : roles) {
            sb.append("&roles=").append(urlForm(r));
        }
        return sb.toString();
    }

    static String formEncodeRolesOnly(List<String> roles) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (String r : roles) {
            if (!first) {
                sb.append("&");
            }
            first = false;
            sb.append("roles=").append(urlForm(r));
        }
        return sb.toString();
    }

    static String urlForm(String v) {
        return URLEncoder.encode(StringUtils.defaultString(v), StandardCharsets.UTF_8);
    }

    static String urlEncodePath(String username) {
        return URLEncoder.encode(username, StandardCharsets.UTF_8).replace("+", "%20");
    }

    static String normalizeBase(String mgmtBaseUrl) {
        if (StringUtils.isBlank(mgmtBaseUrl)) {
            return null;
        }
        String t = mgmtBaseUrl.trim();
        while (t.endsWith("/")) {
            t = t.substring(0, t.length() - 1);
        }
        return t;
    }
}
