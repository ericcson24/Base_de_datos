import mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, unquote
from http.cookies import SimpleCookie
from datetime import datetime
import os
import json
import time
import shutil
import cgi

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Datos"))
USERS_PATH = os.path.join(BASE_DIR, "usuarios.txt")
LOG_PATH = os.path.join(BASE_DIR, "log.txt")

def cargar_usuarios():
    usuarios = {}
    if os.path.exists(USERS_PATH):
        with open(USERS_PATH, "r", encoding="utf-8") as f:
            for linea in f:
                if ":" in linea:
                    usuario, clave = linea.strip().split(":", 1)
                    usuarios[usuario.strip()] = clave.strip()
                else:
                    print(f"⚠️ Línea inválida en usuarios.txt: {linea.strip()}")
    else:
        print("🚫 No se encontró usuarios.txt")
    print("🧪 Usuarios cargados:", usuarios)
    return usuarios

USERS = cargar_usuarios()

    

def guardar_usuario(usuario, clave):
    with open(USERS_PATH, "a", encoding="utf-8") as f:
        f.write(f"{usuario}:{clave}\n")
    ruta_login = os.path.join(BASE_DIR, usuario, "login.txt")
    os.makedirs(os.path.dirname(ruta_login), exist_ok=True)
    with open(ruta_login, "w", encoding="utf-8") as f:
        f.write(f"{usuario}:{clave}\n")

def sincronizar_login_usuario(usuario):
    clave = USERS.get(usuario)
    if clave:
        ruta_login = os.path.join(BASE_DIR, usuario, "login.txt")
        os.makedirs(os.path.dirname(ruta_login), exist_ok=True)
        with open(ruta_login, "w", encoding="utf-8") as f:
            f.write(f"{usuario}:{clave}\n")

def registrar(evento):
    with open(LOG_PATH, "a", encoding="utf-8") as log:
        log.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {evento}\n")

USERS = cargar_usuarios()

class NubeServidor(BaseHTTPRequestHandler):
    def parse_cookies(self):
        cookie_header = self.headers.get("Cookie")
        cookies = {}
        if cookie_header:
            cookie = SimpleCookie()
            cookie.load(cookie_header)
            for key, morsel in cookie.items():
                cookies[key] = morsel.value
        return cookies

    def is_authenticated(self):
        c = self.parse_cookies()
        usuario = c.get("usuario")
        if usuario in USERS and USERS[usuario] == c.get("clave"):
            sincronizar_login_usuario(usuario)
            return True
        return False

    def is_admin(self):
        c = self.parse_cookies()
        return c.get("usuario") == "administrador" and c.get("clave") == "12341234"

    def user_folder(self):
        c = self.parse_cookies()
        tipo = c.get("carpeta", "publica")
        usuario = c.get("usuario", "anonimo")
        carpeta_personal = os.path.join(BASE_DIR, usuario if tipo == "privada" else "Carpeta_compartida")
        os.makedirs(carpeta_personal, exist_ok=True)
        return carpeta_personal

    def clear_cookies(self):
        self.send_header("Set-Cookie", "usuario=; Max-Age=0; Path=/")
        self.send_header("Set-Cookie", "clave=; Max-Age=0; Path=/")
        self.send_header("Set-Cookie", "carpeta=; Max-Age=0; Path=/")

    def require_auth(self, handler_func):
        if not self.is_authenticated():
            self.send_response(302)
            self.clear_cookies()
            self.send_header("Location", "/")
            self.end_headers()
        else:
            handler_func()

    def serve_file(self, filename, content_type):
        try:
            with open(filename, "rb") as f:
                contenido = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(contenido)))
            self.end_headers()
            self.wfile.write(contenido)
        except FileNotFoundError:
            self.send_error(404, f"{filename} no encontrado")

    def _ok(self, mensaje):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(mensaje.encode())

    def _error(self, mensaje):
        self.send_response(400)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(mensaje.encode())

    def do_GET(self):
        inicio = time.time()
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            if path == "/":
                self.serve_file("login_nube.html", "text/html")
            elif path == "/carpetas":
                self.serve_file("carpetas.html", "text/html")
            elif path.endswith(".css"):
                self.serve_file(path.strip("/"), "text/css")
                
            elif path == "/usuarios.json":
                if self.is_admin():
                    data = list(USERS.keys())
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(data).encode())
                else:
                    self.send_error(403, "No autorizado")

            elif path.startswith("/icons/"):
                ruta = os.path.join(os.path.dirname(__file__), path.strip("/"))
                if os.path.exists(ruta):
                    with open(ruta, "rb") as f:
                        contenido = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "image/png")
                    self.send_header("Content-Length", str(len(contenido)))
                    self.end_headers()
                    self.wfile.write(contenido)
                else:
                    self.send_error(404, "Icono no encontrado")
            elif path.startswith("/uploads/"):
                if not self.is_authenticated():
                    self.send_error(403)
                    return
                nombre = unquote(path.replace("/uploads/", ""))
                ruta = os.path.join(self.user_folder(), nombre)
                if os.path.exists(ruta):
                    with open(ruta, "rb") as f:
                        contenido = f.read()
                    tipo = mimetypes.guess_type(ruta)[0] or "application/octet-stream"
                    self.send_response(200)
                    self.send_header("Content-Type", tipo)
                    self.send_header("Content-Length", str(len(contenido)))
                    self.send_header("Content-Disposition", f"inline; filename=\"{nombre}\"")
                    self.end_headers()
                    self.wfile.write(contenido)
                else:
                    self.send_error(404, "Archivo no encontrado")
            elif path == "/panel":
                self.require_auth(lambda: self.handle_panel(parsed))
            elif path == "/logout":
                self.send_response(302)
                self.clear_cookies()
                self.send_header("Location", "/")
                self.end_headers()
            elif path == "/admin":
                if self.is_admin():
                    self.serve_file("admin.html", "text/html")
                else:
                    self.send_error(403, "Acceso denegado")
            
            elif path == "/archivos_usuario":
                if self.is_admin():
                    usuario = parse_qs(parsed.query).get("usuario", [""])[0]
                    ruta = os.path.join(BASE_DIR, usuario)
                    if os.path.exists(ruta):
                        archivos = os.listdir(ruta)
                        visibles = [a for a in archivos if not a.lower().startswith("login")]
                        data = json.dumps(visibles).encode()
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                    else:
                        self.send_error(404, "Carpeta no encontrada")
                else:
                    self.send_error(403, "No autorizado")

            else:
                self.send_error(404, "Ruta no válida")
        finally:
            ping = (time.time() - inicio) * 1000
            print(f"📡 Petición de {self.client_address[0]} | Ping: {ping:.2f} ms")
    def listar_directorio_en_arbol(self, ruta_base):
        print(f"[DEBUG] listar_directorio_en_arbol: {ruta_base}")
        estructura = []
        for nombre in os.listdir(ruta_base):
            ruta = os.path.join(ruta_base, nombre)
            print(f"[DEBUG] Explorando: {ruta}")
            if nombre.lower().startswith("login"):
                print(f"[DEBUG] Ignorando login: {nombre}")
                continue
            if os.path.isdir(ruta):
                print(f"[DEBUG] Es carpeta: {nombre}")
                estructura.append({
                    "nombre": nombre,
                    "tipo": "carpeta",
                    "contenido": self.listar_directorio_en_arbol(ruta)
                })
            else:
                if ruta_base == self.user_folder():
                    ruta_rel = nombre
                else:
                    ruta_rel = os.path.relpath(ruta, self.user_folder())
                ruta_rel = ruta_rel.replace("/", os.sep).replace("\\", os.sep)
                print(f"[DEBUG] Archivo: {nombre} | ruta_rel: {ruta_rel}")
                estructura.append({
                    "nombre": nombre,
                    "tipo": "archivo",
                    "ext": os.path.splitext(nombre)[-1].lower(),
                    "ruta": ruta_rel,
                    "tamano": os.path.getsize(ruta)  # <--- AÑADIDO AQUÍ
                })
        print(f"[DEBUG] Estructura generada para {ruta_base}: {estructura}")
        return estructura


    def handle_panel(self, parsed):
        if parsed.query == "json":
            estructura = self.listar_directorio_en_arbol(self.user_folder())
            data = json.dumps(estructura).encode()

            print("📦 Enviando estructura JSON del panel")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            print("🖥️ Mostrando panel_usuario.html")
            self.serve_file("panel_usuario.html", "text/html")

    def handle_autoupload(self):
        print("📥 Autoupload recibido")
        content_type = self.headers.get("Content-Type", "")
        
        if "multipart/form-data" not in content_type:
            print("❌ Tipo de contenido inválido:", content_type)
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Tipo de contenido invalido.")
            return

        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={"REQUEST_METHOD": "POST"},
            keep_blank_values=True
        )

        usuario = form.getvalue("usuario", "").strip()
        if not usuario:
            print("⚠️ Falta el campo usuario.")
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Falta el nombre de usuario.")
            return

        fileitem = form["file"]
        if not fileitem.filename:
            print("⚠️ No se envió ningún archivo.")
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"No se envio ningun archivo.")
            return

        nombre_archivo = fileitem.filename
        carpeta_usuario = os.path.join(BASE_DIR, usuario, "imagenes de iPhone")
        os.makedirs(carpeta_usuario, exist_ok=True)
        ruta_destino = os.path.join(carpeta_usuario, nombre_archivo)

        try:
            with open(ruta_destino, "wb") as f:
                f.write(fileitem.file.read())
            print(f"✅ Imagen subida a: {ruta_destino}")
            registrar(f"Subida automática desde iPhone: {nombre_archivo}")

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Imagen recibida correctamente.")
        except Exception as e:
            print("❌ Error al guardar la imagen:", e)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Error interno al guardar la imagen.")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        print(f"[DEBUG] do_POST path: {path}")

        if path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length).decode()
            params = parse_qs(data)
            usuario = params.get("usuario", [""])[0]
            clave = params.get("clave", [""])[0]
            if usuario == "administrador" and clave == "12341234":
                self.send_response(302)
                self.send_header("Set-Cookie", f"usuario={usuario}; Path=/; Max-Age=86400; HttpOnly")
                self.send_header("Set-Cookie", f"clave={clave}; Path=/; Max-Age=86400; HttpOnly")
                self.send_header("Location", "/admin")
                self.end_headers()
            elif usuario in USERS and USERS[usuario] == clave:
                print("✅ Login correcto")
                self.send_response(302)
                self.send_header("Set-Cookie", f"usuario={usuario}; Path=/; Max-Age=86400; HttpOnly")
                self.send_header("Set-Cookie", f"clave={clave}; Path=/; Max-Age=86400; HttpOnly")
                self.send_header("Location", "/carpetas")
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                mensaje = "<script>alert('Usuario o contraseña incorrectos'); window.location.href='/'</script>"
                self.wfile.write(mensaje.encode("utf-8"))
            return
    

        if path == "/panel":
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length)
            content_type = self.headers.get("Content-Type", "")
            print(f"[DEBUG] POST /panel content_type: {content_type}")
            print(f"[DEBUG] POST /panel raw data: {data[:200]}...")

            if "multipart/form-data" in content_type:
                boundary = content_type.split("boundary=")[-1].encode()
                parts = data.split(b"--" + boundary)
                for part in parts:
                    if b"filename=" in part:
                        headers, filedata = part.split(b"\r\n\r\n", 1)
                        filedata = filedata.rsplit(b"\r\n", 1)[0]
                        filename = headers.decode().split("filename=")[-1].split("\"")[-2]
                        ruta_relativa = parse_qs(self.path.split("?", 1)[-1]).get("ruta", [""])[0]
                        if not ruta_relativa and b"name=\"ruta\"" in part:
                            try:
                                ruta_info = part.decode(errors="ignore").split("name=\"ruta\"")[-1]
                                ruta_relativa = ruta_info.split("\r\n")[-1].strip()
                            except:
                                ruta_relativa = ""
                        destino = os.path.join(self.user_folder(), ruta_relativa)
                        os.makedirs(destino, exist_ok=True)
                        ruta = os.path.join(destino, filename)

                        with open(ruta, "wb") as f:
                            f.write(filedata)
                        registrar(f"{filename} subido")
                        self.send_response(200)
                        self.end_headers()
                        return

            elif "application/x-www-form-urlencoded" in content_type:
                datos = parse_qs(data.decode())
                print(f"[DEBUG] POST /panel datos: {datos}")
                if "eliminar" in datos:
                    archivo = datos["eliminar"][0].replace("/", os.sep).replace("\\", os.sep)
                    ruta = os.path.join(self.user_folder(), archivo)
                    print(f"[DEBUG] Eliminar archivo: {archivo} | Ruta real: {ruta}")
                    # Normaliza la ruta para soportar / y \ en cualquier sistema
                    archivo = datos["eliminar"][0].replace("/", os.sep).replace("\\", os.sep)
                    ruta = os.path.join(self.user_folder(), archivo)
                    print(f"🗑️ Solicitud para eliminar: {archivo} | Ruta real: {ruta}")
                    if os.path.exists(ruta):
                        try:
                            if os.path.isfile(ruta):
                                os.remove(ruta)
                                print(f"✅ Archivo eliminado: {ruta}")
                                registrar(f"{archivo} eliminado")
                            elif os.path.isdir(ruta):
                                shutil.rmtree(ruta)
                                print(f"📁 Carpeta eliminada: {ruta}")
                                registrar(f"Carpeta '{archivo}' eliminada")
                        except Exception as e:
                            print(f"❌ Error al eliminar {archivo}:", e)
                            self.send_response(500)
                            self.end_headers()
                            return
                        self.send_response(200)
                        self.end_headers()
                    else:
                        print(f"❌ Archivo no encontrado para eliminar: {ruta}")
                        self.send_response(404)
                        self.send_header("Content-Type", "text/plain")
                        self.end_headers()
                        self.wfile.write(b"Archivo no encontrado")

                elif "crear_carpeta" in datos:
                    nombre = datos["crear_carpeta"][0]
                    base = datos.get("base", [""])[0]
                    print(f"[DEBUG] Crear carpeta: {nombre} en base: {base}")
                    destino = os.path.join(self.user_folder(), base)
                    os.makedirs(destino, exist_ok=True)
                    ruta = os.path.join(destino, nombre)

                    os.makedirs(ruta, exist_ok=True)
                    registrar(f"📁 Carpeta '{nombre}' creada en '{base}'")
                    self.send_response(200)
                    self.end_headers()

                elif "mover_archivo" in datos and "destino" in datos:
                    archivo = datos["mover_archivo"][0].replace("/", os.sep).replace("\\", os.sep)
                    destino_raw = datos["destino"][0]
                    # Normaliza destino: raíz si está vacío o solo barras
                    if destino_raw.strip().replace("/", "").replace("\\", "") == "":
                        destino_rel = ""
                    else:
                        destino_rel = destino_raw.replace("/", os.sep).replace("\\", os.sep)
                    ruta_original = os.path.join(self.user_folder(), archivo)
                    print(f"[DEBUG] Mover archivo: {archivo} a destino: {destino_rel}")
                    print(f"[DEBUG] Ruta original: {ruta_original}")
                    if destino_rel == "":
                        destino_dir = self.user_folder()
                        print("[DEBUG] Moviendo a la raíz")
                    else:
                        destino_dir = os.path.join(self.user_folder(), destino_rel)
                        print(f"[DEBUG] Moviendo a la carpeta: {destino_dir}")
                    os.makedirs(destino_dir, exist_ok=True)
                    nombre_archivo = os.path.basename(archivo)
                    nueva_ruta = os.path.join(destino_dir, nombre_archivo)
                    print(f"[DEBUG] Nueva ruta: {nueva_ruta}")
                    try:
                        shutil.move(ruta_original, nueva_ruta)
                        print(f"[DEBUG] Archivo movido de {ruta_original} a {nueva_ruta}")
                        registrar(f"Archivo movido de {archivo} a {destino_rel}")
                        self.send_response(200)
                    except Exception as e:
                        print(f"[DEBUG] Error al mover el archivo: {e}")
                        self.send_response(500)
                    self.end_headers()
                    return

                elif path == "/autoupload":
                    length = int(self.headers.get("Content-Length", 0))
                    data = self.rfile.read(length)
                    content_type = self.headers.get("Content-Type", "")
                    boundary = content_type.split("boundary=")[-1].encode()

                    # Separar partes del cuerpo
                    partes = data.split(b"--" + boundary)
                    nombre_archivo = None
                    datos_imagen = None
                    nombre_usuario = None

                    for parte in partes:
                        if b"filename=" in parte:
                            try:
                                headers, contenido = parte.split(b"\r\n\r\n", 1)
                                contenido = contenido.rsplit(b"\r\n", 1)[0]
                                nombre_archivo = headers.decode(errors="ignore").split("filename=")[-1].split('"')[1]
                                datos_imagen = contenido
                            except Exception as e:
                                print("❌ Error al procesar imagen:", e)
                        elif b'name="usuario"' in parte:
                            try:
                                contenido = parte.split(b"\r\n\r\n", 1)[-1].rsplit(b"\r\n", 1)[0]
                                nombre_usuario = contenido.decode().strip()
                            except Exception as e:
                                print("❌ Error al obtener usuario:", e)

                    if nombre_archivo and datos_imagen and nombre_usuario:
                        ruta_usuario = os.path.join(BASE_DIR, nombre_usuario, "Imágenes de iPhone SBS")
                        os.makedirs(ruta_usuario, exist_ok=True)
                        ruta_guardado = os.path.join(ruta_usuario, nombre_archivo)

                        with open(ruta_guardado, "wb") as f:
                            f.write(datos_imagen)

                        print(f"✅ Imagen subida: {ruta_guardado}")
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b"Imagen subida correctamente")
                    else:
                        print("⚠️ Faltan datos en la solicitud")
                        self.send_response(400)
                        self.end_headers()
                        self.wfile.write(b"Solicitud invalida")

        elif path == "/admin_op" and self.is_admin():
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length).decode()
            params = parse_qs(data)

            if "nuevo" in params and "clave" in params:
                nuevo = params["nuevo"][0]
                clave = params["clave"][0]
                if nuevo not in USERS:
                    guardar_usuario(nuevo, clave)
                    USERS[nuevo] = clave
                    self._ok(f"Usuario '{nuevo}' añadido")
                else:
                    self._error("Usuario ya existe")

            elif "actual" in params:
                actual = params["actual"][0]
                nuevo_nombre = params.get("nuevo_nombre", [actual])[0]
                nueva_clave = params.get("nueva_clave", [USERS.get(actual, '')])[0]
                if actual in USERS:
                    del USERS[actual]
                    with open(USERS_PATH, "w", encoding="utf-8") as f:
                        for u, p in USERS.items():
                            f.write(f"{u}:{p}\n")
                    guardar_usuario(nuevo_nombre, nueva_clave)
                    USERS[nuevo_nombre] = nueva_clave
                    if actual != nuevo_nombre:
                        os.rename(os.path.join(BASE_DIR, actual), os.path.join(BASE_DIR, nuevo_nombre))
                    self._ok(f"Usuario '{actual}' modificado")
                else:
                    self._error("Usuario no existe")

            elif "borrar" in params:
                borrar = params["borrar"][0]
                if borrar in USERS:
                    del USERS[borrar]
                    with open(USERS_PATH, "w", encoding="utf-8") as f:
                        for u, p in USERS.items():
                            f.write(f"{u}:{p}\n")
                    ruta = os.path.join(BASE_DIR, borrar)
                    if os.path.exists(ruta):
                        shutil.rmtree(ruta)
                    self._ok(f"Usuario '{borrar}' eliminado")
                else:
                    self._error("Usuario no encontrado")

PORT = 55888
httpd = HTTPServer(('', PORT), NubeServidor)
print(f"🚀 Servidor corriendo en http://localhost:{PORT}")
httpd.serve_forever()
