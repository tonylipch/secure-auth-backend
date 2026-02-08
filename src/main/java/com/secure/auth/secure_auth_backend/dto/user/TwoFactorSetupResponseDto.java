package com.secure.auth.secure_auth_backend.dto.user;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TwoFactorSetupResponseDto {
    private String secret;
    private String otpAuthUri;
}
