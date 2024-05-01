package com.weektwit.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.weektwit.auth.entity.Token;
import com.weektwit.auth.entity.User;
import com.weektwit.auth.exceptions.UserAlreadyExistException;
import com.weektwit.auth.repository.TokenRepository;
import com.weektwit.auth.repository.UserRepository;
import com.weektwit.auth.wrapper.UserCredentialsWrapper;
import com.weektwit.auth.wrapper.UserInfoWrapper;
import com.weektwit.auth.wrapper.UserWrapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;

    public UserInfoWrapper register(UserWrapper request) {
        checkNotExist(request.getEmail());
        final User user = User.builder()
                .firstname(request.getFirstName())
                .lastname(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();

        final User savedUser = repository.save(user);
        final String jwtToken = jwtService.generateJwtToken(savedUser.getId(), user);
        final String refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(savedUser, jwtToken);

        return UserInfoWrapper
                .builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .firstName(savedUser.getFirstname())
                .lastName(savedUser.getLastname())
                .email(savedUser.getEmail())
                .build();
    }

    private void checkNotExist(String email) {
        userRepository.findByEmail(email)
                .ifPresent(user -> {
                    throw new UserAlreadyExistException("Email is already used: " + email);
                });
    }

    private void saveUserToken(User user, String token) {
        final Token savingtToken = Token
                .builder()
                .user(user)
                .token(token)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(savingtToken);
    }

    public UserInfoWrapper authenticate(UserCredentialsWrapper request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        var user = repository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException(request.getEmail()));

        var jwtToken = jwtService.generateJwtToken(user.getId(), user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return UserInfoWrapper.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .firstName(user.getFirstname())
                .lastName(user.getLastname())
                .email(user.getEmail())
                .build();
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidUserTokens(user.getId());

        if (validUserTokens.isEmpty()) {
            return;
        }

        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });

        tokenRepository.saveAll(validUserTokens);
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail != null) {
            var user = this.repository.findByEmail(userEmail)
                    .orElseThrow();
            if (jwtService.isTokenValid(refreshToken, user)) {
                var accessToken = jwtService.generateJwtToken(user.getId(), user);
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);
                var authResponse = UserInfoWrapper.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .firstName(user.getFirstname())
                        .lastName(user.getLastname())
                        .email(user.getEmail())
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }
}