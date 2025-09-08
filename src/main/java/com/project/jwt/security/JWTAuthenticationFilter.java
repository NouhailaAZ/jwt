package com.project.jwt.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JWTAuthenticationFilter extends OncePerRequestFilter{

    @Autowired
    private JWTGenerator tokenGenerator;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain)throws ServletException, IOException {
     
        try {
            String token = getJWTFromRequest(request);
            
            System.out.println("=== JWT Filter Debug ===");
            System.out.println("Request URI: " + request.getRequestURI());
            System.out.println("Authorization Header: " + request.getHeader("Authorization"));
            System.out.println("Extracted Token: " + (token != null ? "Present (" + token.length() + " chars)" : "Null"));
            
            if(StringUtils.hasText(token)) {
                boolean isValid = tokenGenerator.validatetoken(token);
                System.out.println("Token validation result: " + isValid);
                
                if(isValid) {
                    String username = tokenGenerator.getUsernameFromJWT(token);
                    System.out.println("Username from token: " + username);
                    
                    UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
                    System.out.println("User found: " + userDetails.getUsername());
                    System.out.println("User authorities: " + userDetails.getAuthorities());
                    
                    UsernamePasswordAuthenticationToken authenticationToken = 
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    System.out.println("Authentication set successfully");
                } else {
                    System.out.println("Token validation failed - clearing security context");
                    SecurityContextHolder.clearContext();
                }
            } else {
                System.out.println("No token found in request");
            }
            System.out.println("========================");
            
        } catch (Exception e) {
            System.err.println("JWT Filter Error: " + e.getMessage());
            e.printStackTrace();
            SecurityContextHolder.clearContext();
        }
        
        filterChain.doFilter(request, response);
    }

    private String getJWTFromRequest(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);
        }
        return null;
    }
}