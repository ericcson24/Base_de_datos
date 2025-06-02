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
   ```

4. **Ejecuta el servidor:**

   ```bash
   python Servidor/servidor_nube.py
   ```

5. **Abre tu navegador** y entra en:  
   [http://localhost:8000](http://localhost:8000)

---

## 🗂️ Estructura de carpetas

```
/Servidor/
├── servidor_nube.py         # Servidor principal (HTTP)
├── panel_usuario.html       # Panel de usuario (frontend)
├── panel.css                # Estilos del panel

/Datos/
├── usuarios.txt             # Usuarios y contraseñas (usa hash seguro)
└── ...                      # Carpeta de datos de los usuarios
```

---

## 👤 Usuarios y contraseñas

- Los usuarios se guardan en `/Datos/usuarios.txt` con el formato:

  ```
  usuario:contraseña
  ```

- **Recomendado:** usa hash seguro con `bcrypt` para evitar contraseñas en texto plano.

---

## 🗃️ Funcionalidades principales

- ✅ Subida múltiple de archivos (drag & drop o botón)
- 📁 Creación y borrado de carpetas
- 🔀 Mover archivos y carpetas
- 💾 Cuota de espacio por usuario (por defecto 15 GB, configurable)
- 📊 Barra de progreso visual del espacio ocupado
- 🧑‍💼 Panel de administración para gestionar usuarios

---

## 🔒 Seguridad

- 🔐 **Contraseñas:** usa `bcrypt` para almacenarlas cifradas.
- 🧱 **Aislamiento:** cada usuario solo accede a sus propios archivos.
- 🌐 **HTTPS recomendado:** usa un proxy seguro como Nginx o Caddy si expones el servidor a Internet.
- 🚫 **No expongas:** archivos sensibles como `usuarios.txt` o el código fuente.

---

## ⚙️ Configuración

- **Límite de espacio:** modifica la variable `LIMITE_GB` en `panel_usuario.html`.
- **Puerto del servidor:** edita la línea correspondiente en `servidor_nube.py`.

---

## 🖥️ Panel de usuario

- Visualiza archivos y carpetas
- Barra de espacio ocupado
- Botón para cerrar sesión
- Menú contextual (⋮) para cada archivo y carpeta

---

## 👑 Panel de administración

- Accede como usuario `administrador` (contraseña por defecto: `12341234`)
- Puedes:
  - Añadir nuevos usuarios
  - Cambiar contraseñas
  - Renombrar usuarios
  - Eliminar cuentas

---

## 📦 Backup y restauración

Haz copia de seguridad de la carpeta `/Datos/` para conservar archivos y usuarios.

---

## 📝 Notas

- El sistema está pensado para uso personal o en red local.
- Para cifrado de archivos o extremo a extremo, abre un issue o revisa la documentación extendida.

---

## Capturas

![image](https://github.com/user-attachments/assets/a79f57a4-c59d-46ae-86ee-fe91dd96fc90)


**Desarrollado con ❤️ por Eric**
