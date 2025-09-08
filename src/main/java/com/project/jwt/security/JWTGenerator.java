package com.project.jwt.security;

import java.security.Key;
import java.util.Date;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class JWTGenerator {

    private static final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512);
    
    public String generateToken(Authentication authentication){
        String username = authentication.getName();
        Date currentDate = new Date();
        Date expireDate = new Date(currentDate.getTime() + SecurityConstants.JWT_EXPIRATION);

        System.out.println("=== Token Generation ===");
        System.out.println("Username: " + username);

        System.out.println("Current Date: " + currentDate);
        System.out.println("Expire Date: " + expireDate);
        System.out.println("Duration: " + (SecurityConstants.JWT_EXPIRATION / 1000) + " seconds");
        System.out.println("========================");

        String token = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(currentDate)
                .setExpiration(expireDate)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
        return token;
    }

    public String getUsernameFromJWT(String token){
        Claims claims = Jwts.parser()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    public boolean validatetoken(String token){
        try{
            Claims claims = Jwts.parser()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
            
            Date expiration = claims.getExpiration();
            Date now = new Date();
            
            System.out.println("=== Token Validation ===");
            System.out.println("Token expiration: " + expiration);
            System.out.println("Current time: " + now);
            System.out.println("Is expired: " + expiration.before(now));
            System.out.println("========================");
            
            return !expiration.before(now);
        } catch (ExpiredJwtException ex) {
            System.err.println("JWT Token expired: " + ex.getMessage());
            return false;
        } catch (MalformedJwtException ex) {
            System.err.println("Invalid JWT token: " + ex.getMessage());
            return false;
        } catch (SignatureException ex) {
            System.err.println("JWT signature does not match: " + ex.getMessage());
            return false;
        } catch (UnsupportedJwtException ex) {
            System.err.println("JWT token is unsupported: " + ex.getMessage());
            return false;
        } catch (IllegalArgumentException ex) {
            System.err.println("JWT claims string is empty: " + ex.getMessage());
            return false;
        } catch (Exception ex) {
            System.err.println("JWT validation error: " + ex.getMessage());
            return false;
        }
    }
}