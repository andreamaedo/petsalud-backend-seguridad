package com.petsalud.backendpetsalud.controller;

import com.petsalud.backendpetsalud.dto.LoginRequest;
import com.petsalud.backendpetsalud.dto.LoginResponse;
import com.petsalud.backendpetsalud.security.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class AuthController {

    // Monitoreo básico: deja registro de cada login exitoso y fallido
    private static final Logger log = LoggerFactory.getLogger("SEGURIDAD");

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletRequest http) {
        try {
            // Valida email + contraseña contra la BD (BCrypt) mediante UsuarioDetailsService
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.email(), request.password()));

            UserDetails usuario = (UserDetails) auth.getPrincipal();
            String token = jwtUtil.generarToken(usuario);
            String rol = usuario.getAuthorities().iterator().next().getAuthority();
            log.info("Login exitoso | usuario={} | rol={} | ip={}", usuario.getUsername(), rol, http.getRemoteAddr());

            return ResponseEntity.ok(new LoginResponse(
                    token, "Bearer", usuario.getUsername(), rol, jwtUtil.getExpirationMs()));

        } catch (AuthenticationException e) {
            // se quitan saltos de línea para evitar falsificar líneas del log (log injection)
            String emailSeguro = String.valueOf(request.email()).replaceAll("[\\r\\n]", "_");
            log.warn("Login FALLIDO | email={} | ip={}", emailSeguro, http.getRemoteAddr());
            // Mensaje genérico: no revela si el email existe o si falló la contraseña
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Credenciales inválidas"));
        }
    }
}
