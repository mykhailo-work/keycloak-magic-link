package io.phasetwo.magiclink.filter;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import lombok.extern.jbosslog.JBossLog;
import io.phasetwo.keycloak.magic.auth.token.MagicLinkActionToken;
import jakarta.annotation.Priority;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Context;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.io.IOException;
import java.net.URI;

/**
 * Filter to intercept responses for /login-actions/action-token.
 * If the response has an error status code (4xx or 5xx) — redirects to the redirect_uri from the token.
 */
@Provider
@Priority(Integer.MAX_VALUE)
@JBossLog
public class ActionTokenResponseFilter implements ContainerResponseFilter {

    private static final String PATH_SEGMENT = "login-actions/action-token";

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException {
        String path = requestContext.getUriInfo().getPath();
        if (path == null || !path.contains(PATH_SEGMENT)) {
            return;
        }

        int status = responseContext.getStatus();
        if (status < 400) {
            return;
        }

        String tokenString = requestContext.getUriInfo().getQueryParameters().getFirst("key");
        if (tokenString == null || tokenString.isBlank()) {
            log.warn("Action token missing in request query parameters");
            return;
        }

        try {
            JWSInput input = new JWSInput(tokenString);
            MagicLinkActionToken token = input.readJsonContent(MagicLinkActionToken.class);

            redirectToUri(token.getRedirectUri(), token.getUserId(), responseContext);
        } catch (Exception e) {
            log.error("Failed to process magic link token", e);
        }
    }

    private void redirectToUri(String redirectUri, String userId, ContainerResponseContext responseContext) {
        if (redirectUri == null || redirectUri.isBlank()) {
            log.warnf("Redirect URI is missing for user %s", userId);
            return;
        }

        String redirectWithParams = addQueryParams(redirectUri, userId, redirectUri, responseContext.getStatus());

        log.infof("Redirecting user to %s", redirectWithParams);

        // Perform a 302 redirect
        responseContext.setStatusInfo(Response.Status.FOUND);
        responseContext.getHeaders().clear();
        responseContext.getHeaders().putSingle("Location", URI.create(redirectWithParams).toString());
        responseContext.setEntity(null);
    }

    private String addQueryParams(String baseUri, String userId, String redirectUri, int statusCode) {
        String encodedUserId = URLEncoder.encode(userId, StandardCharsets.UTF_8);
        String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);

        String separator = baseUri.contains("?") ? "&" : "?";
        
        return String.format("%s%skeycloak_user_id=%s&redirect_uri=%s&error_code=%d",
            baseUri, separator, encodedUserId, encodedRedirectUri, statusCode);
    }
}
