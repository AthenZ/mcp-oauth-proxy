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
import io.athenz.mop.model.splunk.SplunkListTokenEntry;
import io.athenz.mop.model.splunk.SplunkListTokensFeedResponse;
import io.athenz.mop.model.splunk.SplunkMessage;
import io.athenz.mop.model.splunk.SplunkMessagesResponse;
import io.athenz.mop.model.splunk.SplunkTokenClaims;
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
import java.util.ArrayList;
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
            throw new SplunkApiException(0, "createUser", "blank Splunk management URL");
        }
        String body = formEncodeUserCreate(username, password, roles);
        postForm(base + "/services/authentication/users?output_mode=json", adminBearer, body, "createUser");
    }

    @Override
    public void updateUserRoles(String mgmtBaseUrl, String adminBearer, String username, List<String> roles) {
        String base = normalizeBase(mgmtBaseUrl);
        if (base == null) {
            throw new SplunkApiException(0, "updateUserRoles", "blank Splunk management URL");
        }
        String body = formEncodeRolesOnly(roles);
        String path = "/services/authentication/users/" + urlEncodePath(username) + "?output_mode=json";
        postForm(base + path, adminBearer, body, "updateUserRoles");
    }

    @Override
    public String mintToken(String mgmtBaseUrl, String adminBearer, String username, String audience, String expiresOn) {
        String base = normalizeBase(mgmtBaseUrl);
        if (base == null) {
            throw new SplunkApiException(0, "mintToken", "blank Splunk management URL");
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
            int status = resp.statusCode();
            if (status != 200 && status != 201) {
                String upstream = parseSplunkMessage(resp.body());
                log.warn("Splunk mintToken failed: status={} user={} upstream={}", status, username, upstream);
                throw new SplunkApiException(status, "mintToken", upstream);
            }
            SplunkTokensFeedResponse feed = objectMapper.readValue(resp.body(), SplunkTokensFeedResponse.class);
            if (feed.entry() == null || feed.entry().isEmpty()) {
                throw new SplunkApiException(status, "mintToken", "no entry in Splunk response");
            }
            var first = feed.entry().get(0);
            var content = first != null ? first.content() : null;
            if (content == null || StringUtils.isBlank(content.token())) {
                throw new SplunkApiException(status, "mintToken", "empty token in Splunk response");
            }
            return content.token();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Splunk mintToken error: {}", e.getMessage());
            throw new SplunkApiException(0, "mintToken", "interrupted: " + e.getMessage());
        } catch (IOException e) {
            log.warn("Splunk mintToken error: {}", e.getMessage());
            throw new SplunkApiException(0, "mintToken", "transport: " + e.getMessage());
        }
    }

    @Override
    public List<SplunkExpiredToken> listExpiredMcpTokens(
            String mgmtBaseUrl, String adminBearer, String subjectPrefix, long nowEpochSeconds) {
        String base = normalizeBase(mgmtBaseUrl);
        if (base == null || StringUtils.isBlank(adminBearer) || StringUtils.isBlank(subjectPrefix)) {
            return List.of();
        }
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(base + "/services/authorization/tokens?output_mode=json&count=0"))
                    .header("Authorization", "Bearer " + adminBearer)
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            HttpResponse<String> resp = splunkHttpExecutor.send(req);
            int status = resp.statusCode();
            if (status < 200 || status >= 300) {
                log.warn("Splunk listExpiredMcpTokens failed: status={}", status);
                return List.of();
            }
            SplunkListTokensFeedResponse feed =
                    objectMapper.readValue(resp.body(), SplunkListTokensFeedResponse.class);
            if (feed == null || feed.entry() == null || feed.entry().isEmpty()) {
                return List.of();
            }
            List<SplunkExpiredToken> out = new ArrayList<>();
            for (SplunkListTokenEntry e : feed.entry()) {
                if (e == null || StringUtils.isBlank(e.name()) || e.content() == null) {
                    continue;
                }
                SplunkTokenClaims claims = e.content().claims();
                if (claims == null || claims.sub() == null) {
                    continue;
                }
                if (!claims.sub().startsWith(subjectPrefix)) {
                    continue;
                }
                if (claims.exp() >= nowEpochSeconds) {
                    continue;
                }
                out.add(new SplunkExpiredToken(e.name(), claims.sub(), claims.exp()));
            }
            return out;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Splunk listExpiredMcpTokens error: {}", e.getMessage());
            return List.of();
        } catch (IOException e) {
            log.warn("Splunk listExpiredMcpTokens error: {}", e.getMessage());
            return List.of();
        }
    }

    @Override
    public boolean deleteToken(String mgmtBaseUrl, String adminBearer, String tokenId) {
        String base = normalizeBase(mgmtBaseUrl);
        if (base == null || StringUtils.isBlank(adminBearer) || StringUtils.isBlank(tokenId)) {
            return false;
        }
        try {
            String path = "/services/authorization/tokens/" + urlEncodePath(tokenId) + "?output_mode=json";
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(base + path))
                    .header("Authorization", "Bearer " + adminBearer)
                    .header("Accept", "application/json")
                    .DELETE()
                    .build();
            HttpResponse<String> resp = splunkHttpExecutor.send(req);
            int status = resp.statusCode();
            if (status < 200 || status >= 300) {
                log.warn("Splunk deleteToken failed: status={} id={}", status, tokenId);
                return false;
            }
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Splunk deleteToken error id={}: {}", tokenId, e.getMessage());
            return false;
        } catch (IOException e) {
            log.warn("Splunk deleteToken error id={}: {}", tokenId, e.getMessage());
            return false;
        }
    }

    private void postForm(String url, String adminBearer, String body, String operation) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Authorization", "Bearer " + adminBearer)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> resp = splunkHttpExecutor.send(req);
            int status = resp.statusCode();
            if (status < 200 || status >= 300) {
                String upstream = parseSplunkMessage(resp.body());
                log.warn("Splunk {} failed: status={} url={} upstream={}", operation, status, url, upstream);
                throw new SplunkApiException(status, operation, upstream);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Splunk {} error: {}", operation, e.getMessage());
            throw new SplunkApiException(0, operation, "interrupted: " + e.getMessage());
        } catch (IOException e) {
            log.warn("Splunk {} error: {}", operation, e.getMessage());
            throw new SplunkApiException(0, operation, "transport: " + e.getMessage());
        }
    }

    /**
     * Best-effort parser for a Splunk REST error body. Iterates {@code messages[]} and returns
     * the first non-blank {@code text}; falls back to the raw body verbatim when the body isn't
     * parseable JSON or no usable {@code text} is present. Returns the literal string {@code "<empty body>"}
     * only when the body is blank, so callers can always rely on a non-null message to surface.
     *
     * <p>Deliberately avoids indexed access (no {@code messages.get(0)}) and any length truncation —
     * the upstream Splunk message is forwarded verbatim into the 401 {@code error_description}.</p>
     */
    String parseSplunkMessage(String body) {
        if (StringUtils.isBlank(body)) {
            return "<empty body>";
        }
        try {
            SplunkMessagesResponse parsed = objectMapper.readValue(body, SplunkMessagesResponse.class);
            if (parsed != null && parsed.messages() != null) {
                for (SplunkMessage m : parsed.messages()) {
                    if (m != null && StringUtils.isNotBlank(m.text())) {
                        return m.text();
                    }
                }
            }
        } catch (IOException ignored) {
            // not JSON, fall through to raw body
        }
        return body;
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
