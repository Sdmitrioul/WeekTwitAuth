package com.weektwit.auth.controller;

import com.weektwit.auth.service.AuthenticationService;
import com.weektwit.auth.wrapper.UserCredentialsWrapper;
import com.weektwit.auth.wrapper.UserInfoWrapper;
import com.weektwit.auth.wrapper.UserWrapper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authorization", description = "Api for sign up, or authorization, or refreshing token")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;

    @Operation(
            summary = "Register user",
            description = "Register user with given email address and passed password")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "successful registration"),
            @ApiResponse(responseCode = "409", description = "duplicate user")
    })
    @PostMapping("/register")
    public ResponseEntity<UserInfoWrapper> register(@RequestBody UserWrapper request) {
        return ResponseEntity.ok(service.register(request));
    }

    @Operation(
            summary = "Authenticate user",
            description = "Authenticate user with given email address and passed password")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "successful authentication")
    })
    @PostMapping("/authenticate")
    public ResponseEntity<UserInfoWrapper> authenticate(
            @RequestBody UserCredentialsWrapper request
    ) {
        return ResponseEntity.ok(service.authenticate(request));
    }

    @Operation(
            summary = "Update user jwt token",
            description = "Update user token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "successful update operation")
    })
    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        service.refreshToken(request, response);
    }
}
