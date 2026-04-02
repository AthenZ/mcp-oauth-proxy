/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.athenz.mop.telemetry;

/**
 * Values for {@code exchange_step} on {@code mop_token_exchange_step_total} and
 * {@code mop_token_exchange_step_duration_seconds}.
 */
public enum ExchangeStep {
    ZTS_JAG_GRANT("zts_jag_grant"),
    ZTS_JAG_EXCHANGE("zts_jag_exchange"),
    ZTS_ATHENZ_ID_TOKEN("zts_athenz_id_token"),
    ZTS_CLIENT_CREDENTIALS("zts_client_credentials"),
    OKTA_TOKEN_EXCHANGE("okta_token_exchange"),
    GCP_ATHENZ_ID_TOKEN("gcp_athenz_id_token"),
    GCP_GOOGLE_STS("gcp_google_sts"),
    UPSTREAM_REFRESH("upstream_refresh"),
    PASS_THROUGH("pass_through");

    private final String value;

    ExchangeStep(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
