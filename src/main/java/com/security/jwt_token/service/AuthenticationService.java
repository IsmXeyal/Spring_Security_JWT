package com.security.jwt_token.service;

import com.security.jwt_token.dto.*;

public interface AuthenticationService {
    JwtAuthenticationResponseDto register(UserRegisterDto registerDto);
    JwtAuthenticationResponseDto login(UserLoginDto loginDto);
    JwtAuthenticationResponseDto refreshToken(RefreshTokenDto refreshTokenDto);
}