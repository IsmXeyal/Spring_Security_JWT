package com.security.jwt_token.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalControllerExceptionHandler {
    // Handle TokenNotFoundException
    @ResponseBody
    @ExceptionHandler(TokenNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public String handleTokenNotFoundException(TokenNotFoundException ex) {
        return ex.getMessage();
    }

    // Handle RefreshTokenNotFoundException
    @ResponseBody
    @ExceptionHandler(RefreshTokenNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public String handleRefreshTokenNotFoundException(RefreshTokenNotFoundException ex) {
        return ex.getMessage();
    }

    // Handle UserAlreadyExistsException
    @ResponseBody
    @ExceptionHandler(UserAlreadyExistsException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public String handleUserAlreadyExistsException(UserAlreadyExistsException ex) {
        return ex.getMessage();
    }

    // Handle InvalidCredentialsException
    @ExceptionHandler(InvalidCredentialsException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ResponseBody
    public String handleInvalidCredentials(InvalidCredentialsException ex) {
        return ex.getMessage();
    }

    // Handle TokenExpiredException
    @ResponseBody
    @ExceptionHandler(TokenExpiredException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String handleTokenExpiredException(TokenExpiredException ex) {
        return ex.getMessage();
    }
}
