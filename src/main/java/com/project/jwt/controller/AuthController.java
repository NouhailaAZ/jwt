package com.project.jwt.controller;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.project.jwt.dto.AuthResponseDTO;
import com.project.jwt.dto.LoginDto;
import com.project.jwt.dto.RegisterDto;
import com.project.jwt.entity.Role;
import com.project.jwt.entity.UserEntity;
import com.project.jwt.repository.RoleRepository;
import com.project.jwt.repository.UserRepository;
import com.project.jwt.security.JWTGenerator;

import jakarta.validation.Valid;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private AuthenticationManager authenticationManager;
    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;
    private JWTGenerator jwtGenerator;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager, UserRepository userRepository, 
                          RoleRepository roleRepository, PasswordEncoder passwordEncoder, JWTGenerator jwtGenerator){
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtGenerator = jwtGenerator;
    }

    @PostMapping("login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginDto loginDto) {
        try {
            // Vérifier si l'utilisateur existe
            if (!userRepository.existsByUsername(loginDto.getUsername())) {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("status", "error");
                errorResponse.put("message", "Nom d'utilisateur introuvable");
                errorResponse.put("error", "USER_NOT_FOUND");
                return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
            }

            // Tenter l'authentification
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    loginDto.getUsername(),
                    loginDto.getPassword()
                )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String token = jwtGenerator.generateToken(authentication);
            
            return new ResponseEntity<>(new AuthResponseDTO(token), HttpStatus.OK);
            
        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", "Erreur lors de l'authentification");
            errorResponse.put("error", "AUTHENTICATION_ERROR");
            return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    // @PostMapping("login")
    // public ResponseEntity<AuthResponseDTO> login(@RequestBody LoginDto loginDto) {
    //     Authentication authentication = authenticationManager.authenticate(
    //         new UsernamePasswordAuthenticationToken(loginDto.getUsername(),
    //         loginDto.getPassword()));
    //     SecurityContextHolder.getContext().setAuthentication(authentication);
    //     String token = jwtGenerator.generateToken(authentication);
    //     return new ResponseEntity<>(new AuthResponseDTO(token), HttpStatus.OK);
    // }

    @PostMapping("register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterDto registerDto) {
        try{
                if(userRepository.existsByUsername(registerDto.getUsername())){
                    Map<String, Object> errorResponse = new HashMap<>();
                        errorResponse.put("status", "error");
                        errorResponse.put("message", "Le nom d'utilisateur est déjà pris");
                        errorResponse.put("error", "USERNAME_ALREADY_EXISTS");
                        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST); 
                }
            
            UserEntity user = new UserEntity();
            user.setUsername(registerDto.getUsername());
            user.setPassword(passwordEncoder.encode(registerDto.getPassword()));
            
            // Assigner le rôle USER par défaut + ADMIN si l'utilisateur est spécifique
            List<Role> roles = new ArrayList<>();
            roles.add(roleRepository.findByName("ROLE_USER").get());
            
            if ("adminUser".equals(registerDto.getUsername())) {
                roles.add(roleRepository.findByName("ROLE_ADMIN").get());
            }
            
            user.setRoles(roles);
            userRepository.save(user);

            return new ResponseEntity<>("User registered success", HttpStatus.OK);
        }catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", "Erreur lors de l'enregistrement");
            errorResponse.put("error", "REGISTRATION_ERROR");
            return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    
}
