package com.secure.auth.secure_auth_backend.controller;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@Slf4j
public class AdminController {

    @GetMapping("/ping")
    public ResponseEntity<String> ping() {
        log.info("REST /api/admin/ping called");
        return ResponseEntity.ok("ADMIN_OK");
    }
}