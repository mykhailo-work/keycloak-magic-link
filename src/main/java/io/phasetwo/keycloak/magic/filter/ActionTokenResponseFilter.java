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

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;

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

            redirectToUri(token.getRedirectUri(), token.getUserId(), responseContext, requestContext);
        } catch (Exception e) {
            log.error("Failed to process magic link token", e);
        }
    }

    private void redirectToUri(
            String redirectUri,
            String userId,
            ContainerResponseContext responseContext,
            ContainerRequestContext requestContext
    ) {
        String baseUri = redirectUri;

        if (baseUri == null || baseUri.isBlank()) {
            log.warnf("Redirect URI is missing for user %s", userId);
            return;
        }

        Integer statusCode = responseContext.getStatus();
        Object entityObj = responseContext.getEntity();
        String entity = entityObj != null ? entityObj.toString() : "";

        if (entity.contains("You are already authenticated as different user")) {
            log.info("Logging out conflicting user");

            String magicLink = requestContext.getUriInfo().getRequestUri().toString();

           // Clear Keycloak session cookies to force logout
            clearAuthCookies(responseContext, requestContext);

            // Perform a 302 redirect
            responseContext.setStatusInfo(Response.Status.FOUND);
            responseContext.getHeaders().add("Location", URI.create(magicLink).toString());
            responseContext.setEntity(null);
        } else {
            String redirectWithParams = addQueryParams(baseUri, userId, redirectUri, statusCode);

            log.infof("Redirecting user to %s", redirectWithParams);

            // Perform a 302 redirect
            responseContext.setStatusInfo(Response.Status.FOUND);
            responseContext.getHeaders().clear();
            responseContext.getHeaders().putSingle("Location", URI.create(redirectWithParams).toString());
            responseContext.setEntity(null);
        }
    }

    private String addQueryParams(String baseUri, String userId, String redirectUri, int statusCode) {
        String encodedUserId = URLEncoder.encode(userId, StandardCharsets.UTF_8);
        String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);

        String separator = baseUri.contains("?") ? "&" : "?";
        
        return String.format("%s%skc_user_id=%s&redirect_uri=%s&error_code=%d",
            baseUri, separator, encodedUserId, encodedRedirectUri, statusCode);
    }

    @Context
    private KeycloakSession session;

    private void clearAuthCookies(ContainerResponseContext responseContext, ContainerRequestContext requestContext) {
            RealmModel realm = session.getContext().getRealm();
            String realmName = realm.getName();
            String path = "/realms/%s/".formatted(realmName);

            log.infof("Clearing auth cookies for realm %s at path %s", realmName, path);

            responseContext.getHeaders().add(
                    "Set-Cookie",
                    "AUTH_SESSION_ID=; Path=%s; Max-Age=0; HttpOnly".formatted(path)
            );
            responseContext.getHeaders().add(
                    "Set-Cookie",
                    "KEYCLOAK_IDENTITY=; Path=%s; Max-Age=0; HttpOnly".formatted(path)
            );
            responseContext.getHeaders().add(
                    "Set-Cookie",
                    "KEYCLOAK_SESSION=; Path=%s; Max-Age=0; HttpOnly".formatted(path)
            );
    }
}
