package com.project.jwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.project.jwt.entity.Role;



public interface RoleRepository extends JpaRepository<Role, Integer>{
    Optional<Role> findByName(String name);

}
