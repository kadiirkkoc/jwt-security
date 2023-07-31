package com.kadir.security.repository;

import com.kadir.security.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Long> {
    Optional<org.springframework.security.core.userdetails.User> findByEmail(String email);
}
