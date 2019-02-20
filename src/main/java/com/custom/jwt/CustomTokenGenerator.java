package com.custom.jwt;


import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.impl.token.ClaimsRetriever;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.keymgt.service.TokenValidationContext;
import org.wso2.carbon.apimgt.keymgt.token.JWTGenerator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.HashMap;
import java.util.Map;

import static org.apache.commons.collections.MapUtils.isNotEmpty;

public class CustomTokenGenerator extends JWTGenerator {

    private static final Log log = LogFactory.getLog(JWTGenerator.class);
    public static final String DISABLE_AUTHORIZATION_CLAIM_CACHE = "DisableAuthorizationClaimCache";

    @Override
    public Map<String, String> populateCustomClaims(TokenValidationContext validationContext) throws APIManagementException {
        ClaimsRetriever claimsRetriever = getClaimsRetriever();
        if (claimsRetriever != null) {

            //fix for https://github.com/wso2/product-apim/issues/4112
            String accessToken = validationContext.getAccessToken();
            AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken);

            Map<String, String> customClaims = getClaimsFromCache(cacheKey);
            if (isNotEmpty(customClaims)) {
                if (log.isDebugEnabled()) {
                    log.debug("The custom claims are retrieved from AuthorizationGrantCache for user : "
                            + validationContext.getValidationInfoDTO().getEndUserName());
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Custom claims are not available in the AuthorizationGrantCache. Hence will be "
                            + "retrieved from the user store for user : " + validationContext.getValidationInfoDTO()
                            .getEndUserName());
                }
            }

            // If claims are not found in AuthorizationGrantCache, they will be retrieved from the userstore.
            String tenantAwareUserName = validationContext.getValidationInfoDTO().getEndUserName();

            try {
                int tenantId = APIUtil.getTenantId(tenantAwareUserName);

                if (tenantId != -1) {
                    UserStoreManager manager = ServiceReferenceHolder.getInstance().
                            getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();

                    String tenantDomain = MultitenantUtils.getTenantDomain(tenantAwareUserName);
                    String[] split = tenantAwareUserName.split(tenantDomain);

                    if (split.length != 1) {
                        log.error("Could not extract username without tenant domain for: " + tenantAwareUserName);
                        return null;
                    }

                    String username = split[0].substring(0, split[0].length() - 1);

                    if (manager.isExistingUser(username)) {
                        customClaims.putAll(claimsRetriever.getClaims(tenantAwareUserName));
                        return customClaims;
                    } else {
                        if (!customClaims.isEmpty()) {
                            return customClaims;
                        } else {
                            log.warn("User " + tenantAwareUserName + " cannot be found by user store manager");
                        }
                    }
                } else {
                    log.error("Tenant cannot be found for username: " + tenantAwareUserName);
                }
            } catch (APIManagementException e) {
                log.error("Error while retrieving claims ", e);
            } catch (UserStoreException e) {
                log.error("Error while retrieving user store ", e);
            }
        }
        return null;
    }

    private static Map<String, String> getClaimsFromCache(AuthorizationGrantCacheKey cacheKey) {

        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByToken(cacheKey);
        if (cacheEntry == null) {
            return new HashMap<String, String>();
        }
        Map<ClaimMapping, String> userAttributes = cacheEntry.getUserAttributes();
        Map<String, String> userClaims = new HashMap<String, String>();
        for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
            userClaims.put(entry.getKey().getRemoteClaim().getClaimUri(), entry.getValue());
        }
        return userClaims;
    }
}
