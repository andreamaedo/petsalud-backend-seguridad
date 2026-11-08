# Petsalud – Backend seguro con Spring Security y JWT

Backend REST de la clínica veterinaria **Petsalud**, asegurado con **Spring Security 6**, **autenticación JWT**, **control de acceso por roles** y protecciones contra **SQL Injection, XSS y CSRF**.

> Asignatura: Desarrollo Backend II (PBY2202) – Actividad sumativa Semana 3, Duoc UC.

## Tecnologías

|Componente|Versión|
|-|-|
|Java|17 (compatible con 21)|
|Spring Boot|3.3.6|
|Spring Security|6.3|
|JJWT (io.jsonwebtoken)|0.12.6|
|MySQL|8.0|
|Maven|wrapper incluido (`mvnw`)|

## Estructura del proyecto

```
src/main/java/com/petsalud/backendpetsalud
├── controller/   Endpoints REST (Auth, Usuario, Mascota, Cita, Expediente, Producto, Venta, Notificacion, Recompensa)
├── dto/          LoginRequest, LoginResponse
├── entity/       Entidades JPA (Usuario, Rol, Mascota, ...)
├── repository/   Repositorios Spring Data JPA
├── security/     SecurityConfig, JwtUtil, JwtAuthenticationFilter,
│                 UsuarioDetails, UsuarioDetailsService, SeguridadService
└── service/      Lógica de negocio
```

## Configuración y ejecución

### 1\. Base de datos

```sql
CREATE DATABASE IF NOT EXISTS petsalud\_db CHARACTER SET utf8mb4;
```

Las tablas se crean automáticamente al iniciar (`spring.jpa.hibernate.ddl-auto=update`).

### 2\. Variables de entorno

Las credenciales **no están en el código**: se leen desde variables de entorno.

|Variable|Descripción|Ejemplo|
|-|-|-|
|`DB\_USER`|Usuario de MySQL (opcional, por defecto `root`)|`root`|
|`DB\_PASSWORD`|Contraseña de MySQL|`\*\*\*\*\*\*\*\*`|
|`JWT\_SECRET`|Clave de firma JWT en Base64, mínimo 256 bits|ver abajo|

Generar un secreto seguro (PowerShell):

```powershell
$b = New-Object byte\[] 48; \[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); \[Convert]::ToBase64String($b)
```

En IntelliJ: **Run → Edit Configurations → Environment variables**:

```
DB\_PASSWORD=tu\_password;JWT\_SECRET=tu\_secreto\_base64
```

### 3\. Ejecutar

```bash
./mvnw spring-boot:run        # Linux / macOS
mvnw.cmd spring-boot:run      # Windows
```

La API queda disponible en `http://localhost:8080`.

## Autenticación (JWT)

1. **Registro** (público, siempre crea rol `CLIENTE`):
`POST /api/usuarios/registro`

```json
   { "email": "cliente1@petsalud.cl", "password": "Cliente123", "nombre": "Ana", "apellido": "Pérez" }
   ```

2. **Login** (público):
`POST /api/login`

```json
   { "email": "cliente1@petsalud.cl", "password": "Cliente123" }
   ```

   Respuesta:

```json
   { "token": "eyJhbGciOi...", "tipo": "Bearer", "email": "cliente1@petsalud.cl", "rol": "CLIENTE", "expiraEnMs": 3600000 }
   ```

3. **Usar el token** en cada petición protegida:

```
   Authorization: Bearer eyJhbGciOi...
   ```

Características del token:

* Firmado con **HMAC-SHA** usando `JWT\_SECRET` (mínimo 256 bits, validado al iniciar).
* Contiene `sub` (email), `rol`, `iss` (`petsalud`), `iat` y `exp`.
* Expira en **1 hora** (`jwt.expiration-ms`).
* En cada petición se valida firma, emisor, expiración y que el usuario siga existiendo.

Para crear usuarios con rol alto (solo el administrador de la BD puede hacerlo):

```sql
UPDATE usuarios SET rol = 'ADMIN'       WHERE email = 'admin@petsalud.cl';
UPDATE usuarios SET rol = 'VETERINARIO' WHERE email = 'vet@petsalud.cl';
```

## Roles y permisos

|Rol en el código|Rol del caso|
|-|-|
|`CLIENTE`|Cliente|
|`VETERINARIO`|Empleado|
|`ADMIN`|Gerente|

Cada endpoint está protegido con `@PreAuthorize`. Las reglas "solo lo propio" las verifica `SeguridadService`, comparando el id del usuario del token con el dueño del recurso.

|Recurso|CLIENTE|VETERINARIO|ADMIN|
|-|-|-|-|
|Productos|Ver|Ver + stock bajo|Todo|
|Usuarios|Solo su perfil (ver/editar)|Ver|Todo|
|Mascotas|Solo las suyas|Ver, crear, editar|Todo|
|Citas|Agendar/ver/cancelar las de sus mascotas|Gestionar y cambiar estado|Todo|
|Expedientes médicos|Ver los de sus mascotas|Crear y ver|Todo|
|Ventas|Comprar y ver las suyas|Ver y registrar|Todo|
|Notificaciones|Solo las suyas|Enviar|Todo|
|Recompensas|Ver las suyas|–|Todo|

Respuestas de error:

* `401 Unauthorized`: token ausente, inválido o expirado.
* `403 Forbidden`: el rol no tiene permiso o el recurso no le pertenece.

## Medidas de seguridad implementadas

|Amenaza|Medida|
|-|-|
|Robo de contraseñas|Hash **BCrypt**; la contraseña nunca se devuelve en las respuestas (`WRITE\_ONLY`).|
|Escalada de privilegios|El registro fuerza el rol `CLIENTE`; el campo `rol` es de solo lectura en el JSON.|
|Acceso no autorizado|JWT obligatorio + `@PreAuthorize` en todos los endpoints + verificación de propiedad.|
|SQL Injection|Spring Data JPA con **consultas parametrizadas** (sin concatenar SQL).|
|XSS|Validación que rechaza `<`, `>` y `javascript:`; respuestas JSON; cabeceras `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`.|
|CSRF|API **stateless** sin cookies de sesión; el JWT viaja en el header `Authorization`, que el navegador no envía automáticamente. Por eso CSRF se desactiva de forma justificada.|
|Fuerza bruta / enumeración|Mensaje genérico "Credenciales inválidas" que no revela si el email existe.|
|Exposición de información|Sin stack traces en errores (`server.error.include-stacktrace=never`); secretos en variables de entorno.|

## Pruebas

En la carpeta [`postman/`](postman/) está la colección `Petsalud-Seguridad.postman\_collection.json` con:

* Registro, login y uso del token.
* Pruebas por rol (CLIENTE, VETERINARIO, ADMIN) con resultados 200 / 401 / 403.
* Pruebas de **SQL Injection**, **XSS** y **CSRF**.

Importar en Postman: **Import → seleccionar el archivo**. Ejecutar primero las tres peticiones de login: cada una guarda su token automáticamente en una variable de la colección.

## Integrantes

* Benjamin Merino
* Andrea Mena

