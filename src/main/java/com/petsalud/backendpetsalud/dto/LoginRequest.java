package com.petsalud.backendpetsalud.dto;

/** Cuerpo del POST /api/login: { "email": "...", "password": "..." } */
public record LoginRequest(String email, String password) {
}
