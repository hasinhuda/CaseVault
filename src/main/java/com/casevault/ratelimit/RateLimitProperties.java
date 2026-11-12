package com.casevault.ratelimit;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration under {@code casevault.ratelimit.*}. Flat primitive properties on purpose (no nested mutable
 * objects). Defaults are conservative starting points, not tuned values.
 */
@Component
@ConfigurationProperties(prefix = "casevault.ratelimit")
public class RateLimitProperties implements RateLimitSettings {

    private boolean enabled = true;
    private boolean trustForwardedFor = false;
    private int maxTrackedKeys = 10_000;

    private int loginLimit = 10;
    private int loginWindowSeconds = 60;
    private int apiBasicLimit = 60;
    private int apiBasicWindowSeconds = 60;
    private int searchLimit = 60;
    private int searchWindowSeconds = 60;
    private int uploadLimit = 10;
    private int uploadWindowSeconds = 60;
    private int reportWriteLimit = 30;
    private int reportWriteWindowSeconds = 60;

    @Override
    public boolean enabled() {
        return enabled;
    }

    @Override
    public boolean trustForwardedFor() {
        return trustForwardedFor;
    }

    @Override
    public int maxTrackedKeys() {
        return Math.max(1, maxTrackedKeys);
    }

    @Override
    public RateRule rule(LimiterName name) {
        return switch (name) {
            case LOGIN -> new RateRule(loginLimit, loginWindowSeconds);
            case API_BASIC -> new RateRule(apiBasicLimit, apiBasicWindowSeconds);
            case SEARCH -> new RateRule(searchLimit, searchWindowSeconds);
            case UPLOAD -> new RateRule(uploadLimit, uploadWindowSeconds);
            case REPORT_WRITE -> new RateRule(reportWriteLimit, reportWriteWindowSeconds);
        };
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public void setTrustForwardedFor(boolean trustForwardedFor) {
        this.trustForwardedFor = trustForwardedFor;
    }

    public void setMaxTrackedKeys(int maxTrackedKeys) {
        this.maxTrackedKeys = maxTrackedKeys;
    }

    public void setLoginLimit(int loginLimit) {
        this.loginLimit = loginLimit;
    }

    public void setLoginWindowSeconds(int loginWindowSeconds) {
        this.loginWindowSeconds = loginWindowSeconds;
    }

    public void setApiBasicLimit(int apiBasicLimit) {
        this.apiBasicLimit = apiBasicLimit;
    }

    public void setApiBasicWindowSeconds(int apiBasicWindowSeconds) {
        this.apiBasicWindowSeconds = apiBasicWindowSeconds;
    }

    public void setSearchLimit(int searchLimit) {
        this.searchLimit = searchLimit;
    }

    public void setSearchWindowSeconds(int searchWindowSeconds) {
        this.searchWindowSeconds = searchWindowSeconds;
    }

    public void setUploadLimit(int uploadLimit) {
        this.uploadLimit = uploadLimit;
    }

    public void setUploadWindowSeconds(int uploadWindowSeconds) {
        this.uploadWindowSeconds = uploadWindowSeconds;
    }

    public void setReportWriteLimit(int reportWriteLimit) {
        this.reportWriteLimit = reportWriteLimit;
    }

    public void setReportWriteWindowSeconds(int reportWriteWindowSeconds) {
        this.reportWriteWindowSeconds = reportWriteWindowSeconds;
    }
}
