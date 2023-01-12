package com.wolin.pizzeria_auth_server.repo;

import com.wolin.pizzeria_auth_server.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role, Integer> {
    Role findByName(String name);
}
