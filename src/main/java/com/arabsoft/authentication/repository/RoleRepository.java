package com.arabsoft.authentication.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.arabsoft.authentication.entity.ERole;
import com.arabsoft.authentication.entity.Role;
import com.arabsoft.authentication.entity.User;

import java.util.List;
import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role,Long> {
    Optional<Role> findByName(ERole name);
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = 'PRESIDENT'")
    List<User> findUsersByRoleUser();
}