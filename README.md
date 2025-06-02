# Base_de_datos

# NubeDistribuible_v2

Una nube personal y sencilla para gestionar tus archivos desde cualquier navegador, con soporte para carpetas, subida, descarga, borrado, cuotas de espacio y panel de administración.

---

## 🚀 ¿Qué es?

**NubeDistribuible_v2** es una aplicación web que te permite:
- Subir, descargar, mover y borrar archivos y carpetas.
- Visualizar el espacio ocupado y el límite de almacenamiento.
- Gestionar usuarios y contraseñas (con posibilidad de cifrado seguro).
- Panel de administración para gestionar usuarios.
- Interfaz moderna y responsive.

---

## 🏁 Instalación rápida

1. **Clona o descarga este repositorio** en tu PC o servidor.
2. **Instala Python 3.8+** (recomendado 3.10+).
3. **Instala dependencias** (opcional, para seguridad):
   ```bash
   pip install bcrypt cryptography



Ejecuta el servidor:
Abre tu navegador y entra en http://localhost:8000
🗂️ Estructura de carpetas
/Servidor/servidor_nube.py — Servidor principal (HTTP)
/Servidor/panel_usuario.html — Panel de usuario (frontend)
/Servidor/panel.css — Estilos del panel
/Datos/usuarios.txt — Usuarios y contraseñas (¡usa hash seguro!)
/Datos/ — Carpeta de datos de usuarios
👤 Usuarios y contraseñas
Los usuarios se guardan en /Datos/usuarios.txt con el formato:
Recomendado: Usa hash seguro (bcrypt) para las contraseñas.
🗃️ Funcionalidades principales
Subida múltiple de archivos (drag & drop o botón)
Creación y borrado de carpetas
Mover archivos y carpetas
Cuota de espacio (por defecto 15 GB, configurable)
Barra de progreso de espacio ocupado
Panel de administración para gestionar usuarios
🔒 Seguridad
Contraseñas: Usa hash seguro (bcrypt) en vez de texto plano.
Archivos: El servidor solo permite acceso a los archivos del usuario autenticado.
HTTPS: Si expones la nube a Internet, usa un proxy HTTPS (Nginx, Caddy, etc).
No expongas archivos sensibles (usuarios.txt, código fuente).
⚙️ Configuración
Límite de espacio:
Edita la variable LIMITE_GB en panel_usuario.html para cambiar la cuota por usuario.
Puerto:
Cambia el puerto en la línea de arranque del servidor si lo necesitas.
🖥️ Panel de usuario
Visualiza tus archivos y carpetas
Barra de espacio ocupado
Botón para cerrar sesión
Menú contextual (tres puntitos) para cada archivo/carpeta
👑 Panel de administración
Accede como usuario administrador para gestionar usuarios.
📦 Backup y restauración
Haz copia de seguridad de la carpeta /Datos/ para guardar usuarios y archivos.
📝 Notas
El sistema está pensado para uso personal o en red local.
Para cifrado de archivos o extremo a extremo, consulta la documentación o abre un issue.
