package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.repository.CitaRepository;
import com.petsalud.backendpetsalud.repository.MascotaRepository;
import com.petsalud.backendpetsalud.repository.NotificacionRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Reglas de "propiedad" que se usan dentro de @PreAuthorize, por ejemplo:
 *   @PreAuthorize("hasAuthority('ADMIN') or @seguridad.esUsuarioActual(#usuarioId)")
 * Así un CLIENTE solo puede ver o modificar SUS datos (sus mascotas, ventas, notificaciones...).
 */
@Component("seguridad")
public class SeguridadService {

    private final MascotaRepository mascotaRepository;
    private final CitaRepository citaRepository;
    private final NotificacionRepository notificacionRepository;

    public SeguridadService(MascotaRepository mascotaRepository,
                            CitaRepository citaRepository,
                            NotificacionRepository notificacionRepository) {
        this.mascotaRepository = mascotaRepository;
        this.citaRepository = citaRepository;
        this.notificacionRepository = notificacionRepository;
    }

    /** id del usuario que hizo la petición (sacado del token JWT), o null si no hay. */
    public Long idUsuarioActual() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof UsuarioDetails detalles) {
            return detalles.getId();
        }
        return null;
    }

    /** true si el id recibido es el del propio usuario autenticado. */
    public boolean esUsuarioActual(Long usuarioId) {
        Long actual = idUsuarioActual();
        return actual != null && actual.equals(usuarioId);
    }

    /** true si la mascota pertenece al usuario autenticado. */
    @Transactional(readOnly = true)
    public boolean esDuenoMascota(Long mascotaId) {
        return mascotaRepository.findById(mascotaId)
                .map(m -> m.getPropietario() != null && esUsuarioActual(m.getPropietario().getId()))
                .orElse(false);
    }

    /** true si la cita es de una mascota del usuario autenticado. */
    @Transactional(readOnly = true)
    public boolean esDuenoCita(Long citaId) {
        return citaRepository.findById(citaId)
                .map(c -> c.getMascota() != null && c.getMascota().getPropietario() != null
                        && esUsuarioActual(c.getMascota().getPropietario().getId()))
                .orElse(false);
    }

    /** true si la notificación está dirigida al usuario autenticado. */
    @Transactional(readOnly = true)
    public boolean esDuenoNotificacion(Long notificacionId) {
        return notificacionRepository.findById(notificacionId)
                .map(n -> n.getUsuario() != null && esUsuarioActual(n.getUsuario().getId()))
                .orElse(false);
    }
}
