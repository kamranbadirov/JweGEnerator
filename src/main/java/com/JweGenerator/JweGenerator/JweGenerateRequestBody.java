package com.JweGenerator.JweGenerator;

public class JweGenerateRequestBody {
    String tenantName;
    String tenantId;
    String expiration;
    String startTime;

    public String getTenantName() {
        return tenantName;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getExpiration() {
        return expiration;
    }

    public String getStartTime() {
        return startTime;
    }

}
