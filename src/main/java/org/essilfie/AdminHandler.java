package org.essilfie;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.essilfie.util.CognitoUtils;
import java.util.List;
import java.util.Map;

public class AdminHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent event, Context context) {
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setHeaders(Map.of("Content-Type", "application/json"));

        try {
            String token = CognitoUtils.extractToken(event);
            List<String> userGroups = CognitoUtils.extractUserGroups(token);

            // Check if user has Admin role
            if (!CognitoUtils.isAdmin(userGroups)) {
                return response
                        .withStatusCode(403)
                        .withBody("{\"message\": \"Access denied. Requires Admin role.\"}");
            }

            // Return admin-only information
            return response
                    .withStatusCode(200)
                    .withBody("{\"message\": \"Welcome, Admin! This is a protected admin endpoint.\"}");

        } catch (Exception e) {
            return response
                    .withStatusCode(500)
                    .withBody("{\"message\": \"Internal server error: " + e.getMessage() + "\"}");
        }
    }
}
