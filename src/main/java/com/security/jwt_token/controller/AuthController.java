package com.security.jwt_token.controller;

import com.security.jwt_token.dto.JwtAuthenticationResponseDto;
import com.security.jwt_token.dto.RefreshTokenDto;
import com.security.jwt_token.dto.UserLoginDto;
import com.security.jwt_token.dto.UserRegisterDto;
import com.security.jwt_token.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationService authService;

    @PostMapping("/register")
    public ResponseEntity<JwtAuthenticationResponseDto> register(@RequestBody UserRegisterDto userRegisterDto) {
        JwtAuthenticationResponseDto response = authService.register(userRegisterDto);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<JwtAuthenticationResponseDto> login(@RequestBody UserLoginDto request) {
        JwtAuthenticationResponseDto response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtAuthenticationResponseDto> refreshToken(@RequestBody RefreshTokenDto refreshTokenDto) {
        return ResponseEntity.ok(authService.refreshToken(refreshTokenDto));
    }
}
