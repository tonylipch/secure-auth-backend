package com.secure.auth.secure_auth_backend.security;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration-seconds}")
    private long jwtExpirationSeconds;

    @Value("${jwt.two-factor-expiration-seconds:300}")
    private long twoFactorExpirationSeconds;

    private SecretKey signingKey;

    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    public String generateAccessToken(UserDetails userDetails) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + (jwtExpirationSeconds * 1000));

        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(now)
                .expiration(expiry)
                .claim("typ", "ACCESS")
                .signWith(signingKey)
                .compact();
    }

    public String generateTwoFactorToken(UserDetails userDetails) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + (twoFactorExpirationSeconds * 1000));

        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(now)
                .expiration(expiry)
                .claim("typ", "TWO_FACTOR")
                .signWith(signingKey)
                .compact();
    }

    @PostConstruct
    void init() {

        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    private boolean isTokenExpired(String token) {
        try {
            Date expiration = parseClaims(token).getExpiration();
            return expiration.before(new Date());
        } catch (ExpiredJwtException ex) {
            return true;
        }
    }

    public boolean isAccessTokenValid(String token, UserDetails userDetails) {
        try {
            String username = extractUsername(token);
            return username.equals(userDetails.getUsername())
                    && isTokenType(token, "ACCESS")
                    && !isTokenExpired(token);
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public boolean isTwoFactorTokenValid(String token, UserDetails userDetails) {
        try {
            String username = extractUsername(token);
            return username.equals(userDetails.getUsername())
                    && isTokenType(token, "TWO_FACTOR")
                    && !isTokenExpired(token);
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public boolean isTokenType(String token, String type) {
        String tokenType = parseClaims(token).get("typ", String.class);
        return type.equals(tokenType);
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
