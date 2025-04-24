package com.security.jwt_token.dto;

import com.security.jwt_token.model.Role;
import lombok.*;

import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserRegisterDto {
    private String firstName;
    private String email;
    private String username;
    private String password;
    private Set<Role> roles;
}
