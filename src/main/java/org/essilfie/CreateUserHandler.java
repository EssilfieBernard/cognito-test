package org.essilfie;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.essilfie.util.CognitoUtils;
import com.google.gson.Gson;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminCreateUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminCreateUserResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminAddUserToGroupRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.DeliveryMediumType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class CreateUserHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final String USER_POOL_ID = System.getenv("USER_POOL_ID");
    private final Gson gson = new Gson();

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent event, Context context) {
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setHeaders(Map.of("Content-Type", "application/json"));

        try {
            // Extract and validate token
            String token = CognitoUtils.extractToken(event);
            if (token == null) {
                return response
                        .withStatusCode(401)
                        .withBody("{\"message\": \"Authentication required\"}");
            }

            List<String> userGroups = CognitoUtils.extractUserGroups(token);

            // Only admins can create users
            if (!CognitoUtils.isAdmin(userGroups)) {
                return response
                        .withStatusCode(403)
                        .withBody("{\"message\": \"Access denied. Only admins can create users.\"}");
            }

            // Parse request body
            CreateUserRequest createUserRequest = gson.fromJson(event.getBody(), CreateUserRequest.class);

            // Validate request
            if (createUserRequest.getEmail() == null || createUserRequest.getEmail().trim().isEmpty()) {
                return response
                        .withStatusCode(400)
                        .withBody("{\"message\": \"Email is required\"}");
            }

            if (createUserRequest.getRole() == null || createUserRequest.getRole().trim().isEmpty()) {
                return response
                        .withStatusCode(400)
                        .withBody("{\"message\": \"Role is required\"}");
            }

            // Validate role
            String role = createUserRequest.getRole();
            if (!role.equals("Admin") && !role.equals("Editor") && !role.equals("Viewer")) {
                return response
                        .withStatusCode(400)
                        .withBody("{\"message\": \"Invalid role. Must be Admin, Editor, or Viewer\"}");
            }

            // Create Cognito client
            CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.builder()
                    .region(Region.of(System.getenv("CUSTOM_AWS_REGION")))
                    .build();

            // Set up user attributes
            List<AttributeType> userAttributes = new ArrayList<>();
            userAttributes.add(AttributeType.builder()
                    .name("email")
                    .value(createUserRequest.getEmail())
                    .build());
            userAttributes.add(AttributeType.builder()
                    .name("email_verified")
                    .value("true")
                    .build());

            // Create the user
            AdminCreateUserRequest createRequest = AdminCreateUserRequest.builder()
                    .userPoolId(USER_POOL_ID)
                    .username(createUserRequest.getEmail())
                    .userAttributes(userAttributes)
                    .desiredDeliveryMediums(DeliveryMediumType.EMAIL)
                    .build();

            AdminCreateUserResponse createResult = cognitoClient.adminCreateUser(createRequest);

            // Add user to specified group
            AdminAddUserToGroupRequest addUserToGroupRequest = AdminAddUserToGroupRequest.builder()
                    .userPoolId(USER_POOL_ID)
                    .username(createUserRequest.getEmail())
                    .groupName(role)
                    .build();

            cognitoClient.adminAddUserToGroup(addUserToGroupRequest);

            return response
                    .withStatusCode(200)
                    .withBody(gson.toJson(Map.of(
                            "message", "User created successfully",
                            "username", createUserRequest.getEmail(),
                            "role", role
                    )));

        } catch (CognitoIdentityProviderException e) {
            context.getLogger().log("Error creating user: " + e.getMessage());
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

    // Request class for user creation
    private static class CreateUserRequest {
        private String email;
        private String role;

        public String getEmail() {
            return email;
        }

        public String getRole() {
            return role;
        }
    }
}
