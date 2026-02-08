package com.secure.auth.secure_auth_backend.service;

import com.secure.auth.secure_auth_backend.dto.user.ChangePasswordRequestDto;
import com.secure.auth.secure_auth_backend.dto.user.TwoFactorSetupResponseDto;
import com.secure.auth.secure_auth_backend.dto.user.TwoFactorVerifyRequestDto;
import com.secure.auth.secure_auth_backend.dto.user.UserProfileDto;
import com.secure.auth.secure_auth_backend.entity.Role;
import com.secure.auth.secure_auth_backend.entity.User;
import com.secure.auth.secure_auth_backend.repository.UserRepository;
import com.secure.auth.secure_auth_backend.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TwoFactorService twoFactorService;

    public UserProfileDto getMyProfile() {
        User user = getCurrentUser();
        Set<String> roles = user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());

        return new UserProfileDto(
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                roles,
                user.isTwoFactorEnabled()
        );
    }

    public void changePassword(ChangePasswordRequestDto request) {
        User user = getCurrentUser();

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Current password is invalid");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }

    public TwoFactorSetupResponseDto setupTwoFactor() {
        User user = getCurrentUser();
        String secret = twoFactorService.generateSecret();
        user.setTwoFactorSecret(secret);
        user.setTwoFactorEnabled(false);
        user.setTwoFactorConfirmedAt(null);
        userRepository.save(user);

        String otpAuthUri = twoFactorService.buildOtpAuthUri(user.getEmail(), secret);
        return new TwoFactorSetupResponseDto(secret, otpAuthUri);
    }

    public void verifyTwoFactor(TwoFactorVerifyRequestDto request) {
        User user = getCurrentUser();

        if (user.getTwoFactorSecret() == null) {
            throw new IllegalStateException("2FA is not initialized");
        }

        boolean valid = twoFactorService.isCodeValid(user.getTwoFactorSecret(), request.getCode(), 1);
        if (!valid) {
            throw new IllegalArgumentException("Invalid OTP code");
        }

        user.setTwoFactorEnabled(true);
        user.setTwoFactorConfirmedAt(LocalDateTime.now());
        userRepository.save(user);
    }

    public void disableTwoFactor(TwoFactorVerifyRequestDto request) {
        User user = getCurrentUser();

        if (!user.isTwoFactorEnabled() || user.getTwoFactorSecret() == null) {
            throw new IllegalStateException("2FA is not enabled");
        }

        boolean valid = twoFactorService.isCodeValid(user.getTwoFactorSecret(), request.getCode(), 1);
        if (!valid) {
            throw new IllegalArgumentException("Invalid OTP code");
        }

        user.setTwoFactorEnabled(false);
        user.setTwoFactorSecret(null);
        user.setTwoFactorConfirmedAt(null);
        userRepository.save(user);
    }

    private User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();

        if (!(principal instanceof CustomUserDetails customUserDetails)) {
            throw new IllegalStateException("Unexpected principal type");
        }

        return customUserDetails.getUser();
    }
}
