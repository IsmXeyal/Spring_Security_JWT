package com.security.jwt_token.dto;

import lombok.*;

import java.util.Date;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtAuthenticationResponseDto {
    private String token;
    private String refreshToken;
    private Date expiresAt;
}
