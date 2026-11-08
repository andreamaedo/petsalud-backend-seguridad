package com.petsalud.backendpetsalud.dto;

/** Respuesta del login. Nunca incluye la contraseña. */
public record LoginResponse(String token, String tipo, String email, String rol, long expiraEnMs) {
}
