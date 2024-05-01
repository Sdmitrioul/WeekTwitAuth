package com.weektwit.auth.service;

import com.weektwit.auth.constant.Auth;
import com.weektwit.auth.repository.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {
    private static final String AUTH_HEADER = Auth.AUTH_HEADER;
    private static final String BEARER_PREFIX = Auth.BEARER_PREFIX;

    private final TokenRepository tokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        final String authHeader = request.getHeader(AUTH_HEADER);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return;
        }

        final String jwt = authHeader.substring(BEARER_PREFIX.length());
        tokenRepository.findByToken(jwt).map(token -> {
            token.setExpired(true);
            token.setRevoked(true);
            tokenRepository.save(token);
            SecurityContextHolder.clearContext();
            return null;
        });
    }
}