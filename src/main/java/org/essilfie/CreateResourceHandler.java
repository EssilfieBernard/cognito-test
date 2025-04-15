package org.essilfie;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.essilfie.model.Resource;
import org.essilfie.util.CognitoUtils;
import com.google.gson.Gson;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class CreateResourceHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final Gson gson = new Gson();

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent event, Context context) {
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setHeaders(Map.of("Content-Type", "application/json"));

        try {
            String token = CognitoUtils.extractToken(event);
            List<String> userGroups = CognitoUtils.extractUserGroups(token);

            // Check if user has Editor or Admin role
            if (!CognitoUtils.isEditor(userGroups)) {
                return response
                        .withStatusCode(403)
                        .withBody("{\"message\": \"Access denied. Requires Editor or Admin role.\"}");
            }

            // Parse the incoming resource
            Resource newResource = gson.fromJson(event.getBody(), Resource.class);

            // Generate a new ID for the resource
            newResource.setId(UUID.randomUUID().toString());

            // In a real application, you would save this to a database
            // For now, we'll just return the created resource
            return response
                    .withStatusCode(201)
                    .withBody(gson.toJson(newResource));

        } catch (Exception e) {
            return response
                    .withStatusCode(500)
                    .withBody("{\"message\": \"Internal server error: " + e.getMessage() + "\"}");
        }
    }
}