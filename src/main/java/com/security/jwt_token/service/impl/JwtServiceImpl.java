package com.security.jwt_token.service.impl;

import com.security.jwt_token.exceptions.TokenNotFoundException;
import com.security.jwt_token.model.Token;
import com.security.jwt_token.repository.TokenRepository;
import com.security.jwt_token.service.JwtService;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.*;
import java.util.function.Function;
import java.security.Key;
import java.util.*;

@Service
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {
    private static final Logger logger = LoggerFactory.getLogger(JwtServiceImpl.class);
    private final TokenRepository tokenRepository;

    @Value("${token.signing.key}")
    private String jwtSigningKey;

    @Value("${token.refresh.signing.key}")
    private String jwtRefreshSigningKey;

    @Value("${token.access.token.expiration}")
    private long accessTokenExpiration;

    @Value("${token.refresh.token.expiration}")
    private long refreshTokenExpiration;

    @Override
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    @Override
    public String generateToken(UserDetails userDetails) {
        logger.info("Generating access token for user '{}'", userDetails.getUsername());
        return generateToken(userDetails, accessTokenExpiration, jwtSigningKey);
    }

    @Override
    public String generateRefreshToken(UserDetails userDetails) {
        logger.info("Generating refresh token for user '{}'", userDetails.getUsername());
        return generateToken(userDetails, refreshTokenExpiration, jwtRefreshSigningKey);
    }

    @Override
    public boolean isTokenValid(String token, UserDetails userDetails) {
        String userName = extractUserName(token);
        Token tokenFromDb = tokenRepository.findByToken(token)
                .orElseThrow(() -> {
                    logger.warn("Token not found in DB: {}", token);
                    return new TokenNotFoundException("Token is invalid: " + token);
                });
        return tokenFromDb.getIsActive() && userName.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private String generateToken(UserDetails userDetails, long expiration, String signingKey) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("authorities", userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList());
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey(signingKey), SignatureAlgorithm.HS256)
                .compact();
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        return claimsResolver.apply(extractAllClaims(token));
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey(jwtSigningKey))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSigningKey(String key) {
        byte[] keyBytes = Decoders.BASE64.decode(key);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
