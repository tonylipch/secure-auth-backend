package com.secure.auth.secure_auth_backend.controller;


import com.secure.auth.secure_auth_backend.dto.auth.AuthResponseDto;
import com.secure.auth.secure_auth_backend.dto.auth.LoginRequestDto;
import com.secure.auth.secure_auth_backend.dto.auth.RegisterRequestDto;
import com.secure.auth.secure_auth_backend.dto.auth.TwoFactorLoginRequestDto;
import com.secure.auth.secure_auth_backend.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequestDto request) {
        log.info("Login attempt for email={}", request.getEmail());

        try {
            AuthResponseDto response = authService.login(request);
            log.info("Login success for email={}", request.getEmail());
            return ResponseEntity.ok(response);

        } catch (AuthenticationException ex) {
            log.warn("Login failed for email={}: {}", request.getEmail(), ex.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

        } catch (Exception ex) {
            log.error("Unexpected error during login for email={}", request.getEmail(), ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponseDto> register(@Valid @RequestBody RegisterRequestDto request) {
        log.info("REST /api/auth/register called for email={}", request.getEmail());

        try {
            AuthResponseDto response = authService.register(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (IllegalArgumentException ex) {
            // email already exists
            log.warn("Registration failed for email={}: {}", request.getEmail(), ex.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();

        } catch (Exception ex) {
            log.error("Unexpected error during registration for email={}", request.getEmail(), ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/login/2fa")
    public ResponseEntity<AuthResponseDto> loginWithTwoFactor(@Valid @RequestBody TwoFactorLoginRequestDto request) {
        try {
            AuthResponseDto response = authService.loginWithTwoFactor(
                    request.getTempToken(),
                    request.getCode()
            );
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception ex) {
            log.error("Unexpected error during 2FA login", ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
