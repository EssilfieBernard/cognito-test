package org.essilfie;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException;

import java.util.HashMap;
import java.util.Map;

public class AuthenticationHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final String CLIENT_ID = System.getenv("USER_POOL_CLIENT_ID");
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent event, Context context) {
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setHeaders(Map.of("Content-Type", "application/json"));

        try {
            // Parse request body
            LoginRequest loginRequest = objectMapper.readValue(event.getBody(), LoginRequest.class);

            // Validate request
            if (loginRequest.getEmail() == null || loginRequest.getEmail().trim().isEmpty()) {
                return response
                        .withStatusCode(400)
                        .withBody("{\"message\": \"Email is required\"}");
            }

            if (loginRequest.getPassword() == null || loginRequest.getPassword().trim().isEmpty()) {
                return response
                        .withStatusCode(400)
                        .withBody("{\"message\": \"Password is required\"}");
            }

            // Create Cognito client
            CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.builder()
                    .region(Region.of(System.getenv("CUSTOM_AWS_REGION")))
                    .build();

            // Set up authentication parameters
            Map<String, String> authParams = new HashMap<>();
            authParams.put("USERNAME", loginRequest.getEmail());
            authParams.put("PASSWORD", loginRequest.getPassword());

            // Authenticate the user
            InitiateAuthRequest authRequest = InitiateAuthRequest.builder()
                    .clientId(CLIENT_ID)
                    .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                    .authParameters(authParams)
                    .build();

            InitiateAuthResponse authResponse = cognitoClient.initiateAuth(authRequest);

            Map<String, String> responseBody = new HashMap<>();
            responseBody.put("message", "Authentication successful");
            responseBody.put("idToken", authResponse.authenticationResult().idToken());
            responseBody.put("accessToken", authResponse.authenticationResult().accessToken());
            responseBody.put("refreshToken", authResponse.authenticationResult().refreshToken());
            responseBody.put("expiresIn", String.valueOf(authResponse.authenticationResult().expiresIn()));

            return response
                    .withStatusCode(200)
                    .withBody(objectMapper.writeValueAsString(responseBody));

        } catch (CognitoIdentityProviderException e) {
            context.getLogger().log("Authentication error: " + e.getMessage());
            return response
                    .withStatusCode(401)
                    .withBody("{\"message\": \"" + e.getMessage() + "\"}");
        } catch (Exception e) {
            context.getLogger().log("Internal error: " + e.getMessage());
            return response
                    .withStatusCode(500)
                    .withBody("{\"message\": \"Internal server error: " + e.getMessage() + "\"}");
        }
    }

    // Request class for login
    private static class LoginRequest {
        private String email;
        private String password;

        // Default constructor needed by Jackson
        public LoginRequest() {
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }
}