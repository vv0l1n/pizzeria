package com.wolin.pizzeria_auth_server.repo;

import com.wolin.pizzeria_auth_server.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepo extends JpaRepository<User, Long> {
    User getUserByEmail(String email);
}
