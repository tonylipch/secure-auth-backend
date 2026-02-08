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
import org.springframework.security.authentication.AuthenticationManager;
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
    private final TwoFactorService twoFactorService;

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
        User user = userDetails.getUser();

        if (user.isTwoFactorEnabled()) {
            String tempToken = jwtService.generateTwoFactorToken(userDetails);
            return new AuthResponseDto(null, null, true, tempToken);
        }

        String token = jwtService.generateAccessToken(userDetails);
        return new AuthResponseDto(token, "Bearer", false, null);
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
        String token = jwtService.generateAccessToken(userDetails);

        return new AuthResponseDto(token, "Bearer", false, null);
    }

    public AuthResponseDto loginWithTwoFactor(String tempToken, String code) {
        String email;
        try {
            email = jwtService.extractUsername(tempToken);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid temp token");
        }
        CustomUserDetails userDetails = (CustomUserDetails) userRepository.findByEmail(email)
                .map(CustomUserDetails::new)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!jwtService.isTwoFactorTokenValid(tempToken, userDetails)) {
            throw new IllegalArgumentException("Invalid temp token");
        }

        User user = userDetails.getUser();
        if (!user.isTwoFactorEnabled() || user.getTwoFactorSecret() == null) {
            throw new IllegalStateException("2FA is not enabled");
        }

        boolean valid = twoFactorService.isCodeValid(user.getTwoFactorSecret(), code, 1);
        if (!valid) {
            throw new IllegalArgumentException("Invalid OTP code");
        }

        String token = jwtService.generateAccessToken(userDetails);
        return new AuthResponseDto(token, "Bearer", false, null);
    }
}
