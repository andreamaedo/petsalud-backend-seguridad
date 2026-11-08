package com.petsalud.backendpetsalud.service;

import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UsuarioServiceImpl implements UsuarioService {

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Usuario registrarUsuario(Usuario usuario) {
        if (usuario.getEmail() == null || usuario.getEmail().isBlank()
                || !usuario.getEmail().matches("^[\\w.+-]+@[\\w-]+(\\.[\\w-]+)+$")) {
            throw new IllegalArgumentException("Email inválido");
        }
        if (usuario.getPassword() == null || usuario.getPassword().length() < 8) {
            throw new IllegalArgumentException("La contraseña debe tener al menos 8 caracteres");
        }
        validarTextoSeguro(usuario);
        if (usuarioRepository.findByEmail(usuario.getEmail()).isPresent()) {
            throw new IllegalArgumentException("El email ya está registrado");
        }

        usuario.setId(null);                                            // no se acepta un id enviado por el cliente
        usuario.setRol(Rol.CLIENTE);                                    // todo registro público es CLIENTE
        usuario.setPassword(passwordEncoder.encode(usuario.getPassword())); // se guarda el hash BCrypt
        return usuarioRepository.save(usuario);
    }

    @Override
    public Optional<Usuario> obtenerUsuarioPorId(Long id) {
        return usuarioRepository.findById(id);
    }

    @Override
    public Optional<Usuario> obtenerUsuarioPorEmail(String email) {
        return usuarioRepository.findByEmail(email);
    }

    @Override
    public Usuario actualizarUsuario(Long id, Usuario usuarioActualizado) {
        validarTextoSeguro(usuarioActualizado);
        return usuarioRepository.findById(id).map(usuario -> {
            usuario.setNombre(usuarioActualizado.getNombre());
            usuario.setApellido(usuarioActualizado.getApellido());
            usuario.setTelefono(usuarioActualizado.getTelefono());
            usuario.setDireccion(usuarioActualizado.getDireccion());
            // No se actualiza email, password ni rol aquí por seguridad
            return usuarioRepository.save(usuario);
        }).orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));
    }

    @Override
    public void eliminarUsuario(Long id) {
        usuarioRepository.deleteById(id);
    }

    @Override
    public List<Usuario> listarUsuarios() {
        return usuarioRepository.findAll();
    }

    /**
     * Protección contra XSS almacenado: rechaza etiquetas HTML/JavaScript en los campos de texto
     * (por ejemplo "<script>alert(1)</script>"), para que nunca queden guardadas en la BD.
     */
    private void validarTextoSeguro(Usuario u) {
        for (String campo : new String[]{u.getNombre(), u.getApellido(), u.getTelefono(), u.getDireccion()}) {
            if (campo != null && (campo.contains("<") || campo.contains(">")
                    || campo.toLowerCase().contains("javascript:"))) {
                throw new IllegalArgumentException("Los datos contienen caracteres no permitidos (< > o javascript:)");
            }
        }
    }
}
