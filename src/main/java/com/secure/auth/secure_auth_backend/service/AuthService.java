package com.secure.auth.secure_auth_backend.service;


import com.secure.auth.secure_auth_backend.dto.auth.AuthResponseDto;
import com.secure.auth.secure_auth_backend.dto.auth.LoginRequestDto;
import com.secure.auth.secure_auth_backend.dto.auth.RegisterRequestDto;
import com.secure.auth.secure_auth_backend.entity.AuthProvider;
import com.secure.auth.secure_auth_backend.entity.Role;
import com.secure.auth.secure_auth_backend.entity.User;
import com.secure.auth.secure_auth_backend.repository.RoleRepository;
import com.secure.auth.secure_auth_backend.repository.UserRepository;
import com.secure.auth.secure_auth_backend.security.CustomUserDetails;
import com.secure.auth.secure_auth_backend.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;


@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthResponseDto login(LoginRequestDto request) {
        Authentication authentication;

        try {
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    );


            authentication = authenticationManager.authenticate(authToken);


        } catch (AuthenticationException ex) {
            throw ex;
        }

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        String token = jwtService.generateToken(userDetails);
        return new AuthResponseDto(token, "Bearer");
    }

    public AuthResponseDto register(RegisterRequestDto request) {
        log.info("Registering new user with email={}", request.getEmail());

        // control if email is free
        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Registration failed: email {} already exists", request.getEmail());
            throw new IllegalArgumentException("Email already in use");
        }

        // find user by role
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new IllegalStateException("ROLE_USER not found"));

        // create new user
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .enabled(true)
                .locked(false)
                .provider(AuthProvider.LOCAL)
                .roles(Set.of(userRole))
                .build();

        userRepository.save(user);

        //generate token for usual login
        CustomUserDetails userDetails = new CustomUserDetails(user);
        String token = jwtService.generateToken(userDetails);

        return new AuthResponseDto(token, "Bearer");
    }
}