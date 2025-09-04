# LULAC Membership Portal

Portal web para la gestión de miembros de LULAC, desarrollado con Flask y PostgreSQL.

## Características

- Registro y autenticación de usuarios
- Directorio de miembros con filtros y paginación
- Edición de perfil y cambio de contraseña
- Interfaz moderna y responsiva con Bootstrap
- Base de datos PostgreSQL en la nube (Render)

## Instalación local

1. Clona el repositorio:
   ```
   git clone https://github.com/tu-usuario/LULAC-DIRECTORY.git
   cd LULAC-DIRECTORY
   ```

2. Instala dependencias:
   ```
   pip install -r requirements.txt
   ```

3. Configura la variable de entorno `DATABASE_URL` con la URL de tu base PostgreSQL.

4. Ejecuta la aplicación:
   ```
   flask run
   ```

## Despliegue en Render

1. Sube tu código a GitHub.
2. Crea una base de datos PostgreSQL en Render y copia la `DATABASE_URL`.
3. Crea un nuevo servicio web en Render y conecta tu repositorio.
4. Agrega la variable de entorno `DATABASE_URL` en la configuración del servicio.
5. Render instalará dependencias y levantará tu app automáticamente.

## Estructura de la base de datos

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    area TEXT,
    email TEXT UNIQUE NOT NULL,
    phone TEXT,
    council_number INTEGER,
    city TEXT,
    state TEXT,
    occupation TEXT,
    additional_info TEXT,
    password_hash TEXT NOT NULL
);
```

## Créditos

Programado por **Kamila G**