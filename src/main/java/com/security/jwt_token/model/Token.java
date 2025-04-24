package com.security.jwt_token.model;

import jakarta.persistence.*;
import lombok.*;

import java.util.Date;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;
    String token;
    String refreshToken;
    Date expiresAt;
    @ManyToOne
    @JoinColumn(name = "user_id")
    User user;
    Boolean isActive;

    public Token(String jwt, String refreshToken, Date expiresAt, User user,Boolean isActive) {
        this.token = jwt;
        this.refreshToken = refreshToken;
        this.expiresAt = expiresAt;
        this.user = user;
        this.isActive = isActive;
    }
}
