package com.arabsoft.authentication.service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.arabsoft.authentication.configuration.Payload.JwtResponse;
import com.arabsoft.authentication.configuration.Payload.LoginRequest;
import com.arabsoft.authentication.configuration.Payload.MessageResponse;
import com.arabsoft.authentication.configuration.Payload.SignupRequest;
import com.arabsoft.authentication.configuration.jwt.JwtUtils;
import com.arabsoft.authentication.entity.ERole;
import com.arabsoft.authentication.entity.Role;
import com.arabsoft.authentication.entity.User;
import com.arabsoft.authentication.interfaceImpl.AuthenticationService;
import com.arabsoft.authentication.repository.RoleRepository;
import com.arabsoft.authentication.repository.UserRepository;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {
    
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder encoder;

    @Override
    public JwtResponse authenticateUser(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles);
    }

   @Override
    public MessageResponse registerUser(SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return new MessageResponse("Error: Username is already taken!");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return new MessageResponse("Error: Email is already in use!");
        }

        User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<Role> roles = new HashSet<>();
        if (signUpRequest.getRole() == null || signUpRequest.getRole().isEmpty()) {
            Role userRole = roleRepository.findByName(ERole.PRESIDENT)
                    .orElseThrow(() -> new RuntimeException("Error: Role PRESIDENT is not found."));
            roles.add(userRole);
        } else {
            signUpRequest.getRole().forEach(role -> {
                switch (role.toLowerCase()) {
                    case "validateur":
                        Role responsableRole = roleRepository.findByName(ERole.VALIDATEUR)
                                .orElseThrow(() -> new RuntimeException("Error: Role VALIDATEUR is not found."));
                        roles.add(responsableRole);
                        break;
                    case "president":
                        Role userRole = roleRepository.findByName(ERole.PRESIDENT)
                                .orElseThrow(() -> new RuntimeException("Error: Role PRESIDENT is not found."));
                        roles.add(userRole);
                        break;
                    default:
                        throw new RuntimeException("Error: Invalid role specified!");
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return new MessageResponse("User registered successfully!");
    }

}
