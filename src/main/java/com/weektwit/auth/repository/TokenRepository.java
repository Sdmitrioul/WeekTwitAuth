package com.weektwit.auth.repository;

import com.weektwit.auth.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByToken(String token);

    @Query(value = "select t from Token t where t.user.id = :id and not (t.expired or t.revoked)")
    List<Token> findAllValidUserTokens(Long id);
}
