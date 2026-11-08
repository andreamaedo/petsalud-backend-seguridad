package com.petsalud.backendpetsalud.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

/**
 * Genera y valida tokens JWT firmados con HMAC-SHA (HS384/HS512 según el largo del secreto).
 * El secreto se lee desde la variable de entorno JWT_SECRET (nunca se escribe en el código).
 */
@Component
public class JwtUtil {

    private final SecretKey key;
    private final long expirationMs;

    public JwtUtil(@Value("${jwt.secret}") String secret,
                   @Value("${jwt.expiration-ms}") long expirationMs) {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        if (keyBytes.length < 32) {
            throw new IllegalStateException("JWT_SECRET debe tener al menos 256 bits (32 bytes)");
        }
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.expirationMs = expirationMs;
    }

    /** Crea un token con el email como subject y el rol como claim. */
    public String generarToken(UserDetails usuario) {
        String rol = usuario.getAuthorities().iterator().next().getAuthority();
        Date ahora = new Date();
        return Jwts.builder()
                .subject(usuario.getUsername())
                .claim("rol", rol)
                .issuer("petsalud")
                .issuedAt(ahora)
                .expiration(new Date(ahora.getTime() + expirationMs))
                .signWith(key)
                .compact();
    }

    /** Devuelve el email (subject) del token. Lanza JwtException si el token no es válido. */
    public String obtenerEmail(String token) {
        return leerClaims(token).getSubject();
    }

    /** true si la firma es correcta, no está expirado y pertenece al usuario indicado. */
    public boolean esTokenValido(String token, UserDetails usuario) {
        try {
            Claims claims = leerClaims(token);
            return claims.getSubject().equals(usuario.getUsername())
                    && claims.getExpiration().after(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public long getExpirationMs() {
        return expirationMs;
    }

    private Claims leerClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .requireIssuer("petsalud")
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
