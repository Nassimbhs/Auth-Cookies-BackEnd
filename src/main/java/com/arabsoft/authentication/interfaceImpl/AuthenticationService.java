package com.arabsoft.authentication.interfaceImpl;

import com.arabsoft.authentication.configuration.Payload.JwtResponse;
import com.arabsoft.authentication.configuration.Payload.LoginRequest;
import com.arabsoft.authentication.configuration.Payload.MessageResponse;
import com.arabsoft.authentication.configuration.Payload.SignupRequest;

public interface AuthenticationService {
        JwtResponse authenticateUser(LoginRequest loginRequest);
        MessageResponse registerUser(SignupRequest signUpRequest);
}
