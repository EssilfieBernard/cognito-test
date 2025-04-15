package org.essilfie;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.essilfie.model.Resource;
import org.essilfie.util.CognitoUtils;
import com.google.gson.Gson;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class GetResourcesHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final Gson gson = new Gson();

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent event, Context context) {
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setHeaders(Map.of("Content-Type", "application/json"));

        try {
            String token = CognitoUtils.extractToken(event);
            List<String> userGroups = CognitoUtils.extractUserGroups(token);

            // Check if user has at least Viewer role
            if (!CognitoUtils.isViewer(userGroups)) {
                return response
                        .withStatusCode(403)
                        .withBody("{\"message\": \"Access denied. Requires at least Viewer role.\"}");
            }

            // Mock resource data - in a real application, this would come from a database
            List<Resource> resources = new ArrayList<>();
            resources.add(new Resource("1", "Resource 1", "Description 1"));
            resources.add(new Resource("2", "Resource 2", "Description 2"));

            return response
                    .withStatusCode(200)
                    .withBody(gson.toJson(resources));

        } catch (Exception e) {
            return response
                    .withStatusCode(500)
                    .withBody("{\"message\": \"Internal server error: " + e.getMessage() + "\"}");
        }
    }
}
