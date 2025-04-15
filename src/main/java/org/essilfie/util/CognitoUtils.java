package org.essilfie.util;


import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.util.List;
import java.util.Map;
import java.util.Collections;

public class CognitoUtils {

    public static String extractToken(APIGatewayProxyRequestEvent event) {
        if (event == null) {
            return null;
        }

        Map<String, String> headers = event.getHeaders();
        if (headers != null && headers.containsKey("Authorization")) {
            String authHeader = headers.get("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                return authHeader.substring(7);
            }
        }
        return null;
    }

    public static List<String> extractUserGroups(String token) {
        if (token == null) {
            return Collections.emptyList();
        }

        try {
            DecodedJWT jwt = JWT.decode(token);
            // Check if the claim exists and is not null
            if (jwt.getClaim("cognito:groups").isNull()) {
                return Collections.emptyList();
            }
            return jwt.getClaim("cognito:groups").asList(String.class);
        } catch (Exception e) {
            System.err.println("Error extracting groups: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    public static boolean hasRole(List<String> userGroups, String requiredRole) {
        if (userGroups == null) {
            return false;
        }
        return userGroups.contains(requiredRole);
    }

    public static boolean isAdmin(List<String> userGroups) {
        return hasRole(userGroups, "Admin");
    }

    public static boolean isEditor(List<String> userGroups) {
        return hasRole(userGroups, "Editor") || isAdmin(userGroups);
    }

    public static boolean isViewer(List<String> userGroups) {
        return hasRole(userGroups, "Viewer") || isEditor(userGroups);
    }
}
