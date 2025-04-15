package org.essilfie;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.Gson;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.SignUpRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.SignUpResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class RegisterUserHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final String CLIENT_ID = System.getenv("USER_POOL_CLIENT_ID");
    private final Gson gson = new Gson();

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent event, Context context) {
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setHeaders(Map.of("Content-Type", "application/json"));

        try {
            // Parse request body
            RegistrationRequest registrationRequest = gson.fromJson(event.getBody(), RegistrationRequest.class);

            // Validate request
            if (registrationRequest.getEmail() == null || registrationRequest.getEmail().trim().isEmpty()) {
                return response
                        .withStatusCode(400)
                        .withBody("{\"message\": \"Email is required\"}");
            }

            if (registrationRequest.getPassword() == null || registrationRequest.getPassword().trim().isEmpty()) {
                return response
                        .withStatusCode(400)
                        .withBody("{\"message\": \"Password is required\"}");
            }

            // Create Cognito client
            CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.builder()
                    .region(Region.of(System.getenv("CUSTOM_AWS_REGION")))
                    .build();

            // Set up user attributes
            List<AttributeType> userAttributes = new ArrayList<>();
            userAttributes.add(AttributeType.builder()
                    .name("email")
                    .value(registrationRequest.getEmail())
                    .build());

            // Register the user
            SignUpRequest signUpRequest = SignUpRequest.builder()
                    .clientId(CLIENT_ID)
                    .username(registrationRequest.getEmail())
                    .password(registrationRequest.getPassword())
                    .userAttributes(userAttributes)
                    .build();

            SignUpResponse signUpResponse = cognitoClient.signUp(signUpRequest);

            return response
                    .withStatusCode(200)
                    .withBody(gson.toJson(Map.of(
                            "message", "User registered successfully. Please check your email for verification code.",
                            "userConfirmed", signUpResponse.userConfirmed(),
                            "userSub", signUpResponse.userSub()
                    )));

        } catch (CognitoIdentityProviderException e) {
            context.getLogger().log("Error registering user: " + e.getMessage());
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
}
