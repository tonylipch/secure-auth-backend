package com.secure.auth.secure_auth_backend.controller;


import com.secure.auth.secure_auth_backend.dto.user.ChangePasswordRequestDto;
import com.secure.auth.secure_auth_backend.dto.user.TwoFactorSetupResponseDto;
import com.secure.auth.secure_auth_backend.dto.user.TwoFactorVerifyRequestDto;
import com.secure.auth.secure_auth_backend.dto.user.UserProfileDto;
import com.secure.auth.secure_auth_backend.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {
    private final UserService userService;

    @GetMapping("/me")
    public UserProfileDto me() {
        return userService.getMyProfile();
    }

    @PostMapping("/change-password")
    public ResponseEntity<Void> changePassword(@Valid @RequestBody ChangePasswordRequestDto request) {
        userService.changePassword(request);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/2fa/setup")
    public TwoFactorSetupResponseDto setupTwoFactor() {
        return userService.setupTwoFactor();
    }

    @PostMapping("/2fa/verify")
    public ResponseEntity<Void> verifyTwoFactor(@Valid @RequestBody TwoFactorVerifyRequestDto request) {
        userService.verifyTwoFactor(request);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/2fa/disable")
    public ResponseEntity<Void> disableTwoFactor(@Valid @RequestBody TwoFactorVerifyRequestDto request) {
        userService.disableTwoFactor(request);
        return ResponseEntity.noContent().build();
    }
}
