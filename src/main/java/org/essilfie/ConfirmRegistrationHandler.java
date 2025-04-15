package org.essilfie;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.Gson;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ConfirmSignUpRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ConfirmSignUpResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminAddUserToGroupRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException;

import java.util.Map;

public class ConfirmRegistrationHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final String CLIENT_ID = System.getenv("USER_POOL_CLIENT_ID");
    private final String USER_POOL_ID = System.getenv("USER_POOL_ID");
    private final Gson gson = new Gson();

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent event, Context context) {
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setHeaders(Map.of("Content-Type", "application/json"));

        try {
            // Parse request body
            ConfirmationRequest confirmationRequest = gson.fromJson(event.getBody(), ConfirmationRequest.class);

            // Validate request
            if (confirmationRequest.getEmail() == null || confirmationRequest.getEmail().trim().isEmpty()) {
                return response
                        .withStatusCode(400)
                        .withBody("{\"message\": \"Email is required\"}");
            }

            if (confirmationRequest.getConfirmationCode() == null || confirmationRequest.getConfirmationCode().trim().isEmpty()) {
                return response
                        .withStatusCode(400)
                        .withBody("{\"message\": \"Confirmation code is required\"}");
            }

            // Create Cognito client
            CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.builder()
                    .region(Region.of(System.getenv("AWS_REGION")))
                    .build();

            // Confirm the user registration
            ConfirmSignUpRequest confirmSignUpRequest = ConfirmSignUpRequest.builder()
                    .clientId(CLIENT_ID)
                    .username(confirmationRequest.getEmail())
                    .confirmationCode(confirmationRequest.getConfirmationCode())
                    .build();

            ConfirmSignUpResponse confirmSignUpResponse = cognitoClient.confirmSignUp(confirmSignUpRequest);

            // Add user to the Viewer group by default
            AdminAddUserToGroupRequest addUserToGroupRequest = AdminAddUserToGroupRequest.builder()
                    .userPoolId(USER_POOL_ID)
                    .username(confirmationRequest.getEmail())
                    .groupName("Viewer")  // Default role for self-registered users
                    .build();

            cognitoClient.adminAddUserToGroup(addUserToGroupRequest);

            return response
                    .withStatusCode(200)
                    .withBody("{\"message\": \"User confirmed successfully and assigned to Viewer role\"}");

        } catch (CognitoIdentityProviderException e) {
            context.getLogger().log("Error confirming user: " + e.getMessage());
            return response
                    .withStatusCode(400)
                    .withBody("{\"message\": \"" + e.getMessage() + "\"}");
        } catch (Exception e) {
            context.getLogger().log("Internal error: " + e.getMessage());
            return response
                    .withStatusCode(500)
                    .withBody("{\"message\": \"Internal server error: " + e.getMessage() + "\"}");
        }
    }

    // Request class for confirmation
    private static class ConfirmationRequest {
        private String email;
        private String confirmationCode;

        public String getEmail() {
            return email;
        }

        public String getConfirmationCode() {
            return confirmationCode;
        }
    }
}
