package com.secure.auth.secure_auth_backend.service;

import org.apache.commons.codec.binary.Base32;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Service
public class TwoFactorService {

    private static final int SECRET_SIZE = 20;
    private static final int CODE_DIGITS = 6;
    private static final int TIME_STEP_SECONDS = 30;

    private final SecureRandom secureRandom = new SecureRandom();
    private final Base32 base32 = new Base32();

    @Value("${app.2fa.issuer:SecureAuth}")
    private String issuer;

    public String generateSecret() {
        byte[] buffer = new byte[SECRET_SIZE];
        secureRandom.nextBytes(buffer);
        return base32.encodeToString(buffer).replace("=", "");
    }

    public String buildOtpAuthUri(String email, String secret) {
        String label = issuer + ":" + email;
        return "otpauth://totp/" + urlEncode(label) +
                "?secret=" + secret +
                "&issuer=" + urlEncode(issuer) +
                "&algorithm=SHA1&digits=" + CODE_DIGITS +
                "&period=" + TIME_STEP_SECONDS;
    }

    public boolean isCodeValid(String secretBase32, String code, int window) {
        if (secretBase32 == null || code == null || code.length() != CODE_DIGITS) {
            return false;
        }
        int codeInt;
        try {
            codeInt = Integer.parseInt(code);
        } catch (NumberFormatException ex) {
            return false;
        }

        long currentTimeSeconds = Instant.now().getEpochSecond();
        long timeWindow = currentTimeSeconds / TIME_STEP_SECONDS;

        for (int i = -window; i <= window; i++) {
            if (generateTotp(secretBase32, timeWindow + i) == codeInt) {
                return true;
            }
        }
        return false;
    }

    private int generateTotp(String secretBase32, long timeWindow) {
        byte[] key = base32.decode(secretBase32);
        byte[] data = ByteBuffer.allocate(8).putLong(timeWindow).array();

        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0x0F;
            int binary =
                    ((hash[offset] & 0x7F) << 24) |
                            ((hash[offset + 1] & 0xFF) << 16) |
                            ((hash[offset + 2] & 0xFF) << 8) |
                            (hash[offset + 3] & 0xFF);

            return binary % (int) Math.pow(10, CODE_DIGITS);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate TOTP", ex);
        }
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
