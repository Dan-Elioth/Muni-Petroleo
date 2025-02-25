import io
import re
import sqlite3

import matplotlib
import pandas as pd

matplotlib.use('Agg')  # Usar el backend Agg antes de importar pyplot
import secrets
from datetime import datetime, timedelta
from functools import wraps
from threading import Thread

import matplotlib.pyplot as plt
import pandas as pd
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from bs4 import BeautifulSoup
from flask import (Flask, Response, abort, flash, jsonify, redirect,
                   render_template, request, send_file, send_from_directory,
                   url_for)
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from gensim.models import Word2Vec
from gensim.utils import simple_preprocess
from sklearn.metrics.pairwise import cosine_similarity
from weasyprint import HTML
from werkzeug.security import check_password_hash, generate_password_hash

# Importación de funciones y configuración de base de datos desde `database.py`
from database import \
    get_noticias_count_by_date_range  # Renombrar correctamente esta función para el conteo de noticias en rango
from database import (  # Funciones para Diario Correo; Funciones para El Peruano
    cursor, db, get_noticias_por_dia)

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'


# Configuración de Flask-Login

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"

class User(UserMixin):
    def __init__(self, id, username, password_hash, role_id, estado, area_id):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role_id = role_id
        self.estado = estado
        self.area_id = area_id  # Agrega este atributo

    @staticmethod
    def get_user_by_username(username):
        cursor.execute("SELECT id, username, password_hash, role_id, estado FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        if user_data:
            return User(*user_data)  # Pasamos todos los datos al constructor
        return None


    @staticmethod
    def get_user_by_id(user_id):
        cursor.execute("SELECT id, username, password_hash, role_id FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            return User(user_data[0], user_data[1], user_data[2], user_data[3])
        return None

@login_manager.user_loader
def load_user(user_id):
    cursor.execute("SELECT id, username, password_hash, role_id, estado, area_id FROM users WHERE id = %s", (user_id,))
    user_data = cursor.fetchone()
    if user_data:
        return User(*user_data)  # Ahora incluye `area_id`
    return None



# Función para convertir fechas relativas a absolutas
def convertir_fecha_relativa(fecha_relativa):
    ahora = datetime.now()
    match = re.search(r'(\d+)\s*(hora|horas|día|días|minuto|minutos|semana|semanas)\s*atrás', fecha_relativa)
    if match:
        cantidad = int(match.group(1))
        unidad = match.group(2)
        if 'hora' in unidad:
            fecha = ahora - timedelta(hours=cantidad)
        elif 'día' in unidad:
            fecha = ahora - timedelta(days=cantidad)
        elif 'minuto' in unidad:
            fecha = ahora - timedelta(minutes=cantidad)
        elif 'semana' in unidad:
            fecha = ahora - timedelta(weeks=cantidad)
        else:
            return ahora
        return fecha.strftime('%Y-%m-%d %H:%M:%S')
    return ahora.strftime('%Y-%m-%d %H:%M:%S')

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash("Ya has iniciado sesión.", "info")
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.get_user_by_username(username)  # Incluye is_approved
        
        if user and check_password_hash(user.password_hash, password):
            if user.estado == 0:  # Si no está aprobado
                flash("Tu cuenta está pendiente de aprobación por un administrador.", "warning")
                return redirect(url_for('login'))
            login_user(user)
            flash("Inicio de sesión exitoso", "success")
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        else:
            flash("Usuario o contraseña incorrectos", "error")
            return redirect(url_for('login'))

    return render_template('login.html')



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Has cerrado sesión correctamente.", "success")
    return redirect(url_for('inicio'))

@app.route('/admin/manage_roles', methods=['GET', 'POST'])
@login_required
def manage_roles():
    if current_user.role_id != 1:  # Solo los administradores pueden acceder
        flash("No tienes permiso para acceder a esta página.", "danger")
        return redirect(url_for('inicio'))

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        new_role = request.form.get('new_role')

        try:
            cursor.execute(
                "UPDATE users SET role_id = %s WHERE id = %s",
                (new_role, user_id)
            )
            db.commit()
            flash("Rol actualizado con éxito.", "success")
        except Exception as e:
            flash(f"Error al actualizar el rol: {str(e)}", "danger")

    # Obtener lista de usuarios y roles
    cursor.execute("SELECT id, username, role_id FROM users")
    users = cursor.fetchall()
    roles = [
        (1, "Administrador"),
        (2, "Usuario Premium"),
        (3, "Usuario Regular"),
    ]

    return render_template('manage_roles.html', users=users, roles=roles)


import os

from werkzeug.utils import secure_filename

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limite de tamaño: 16MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Crear carpeta de uploads si no existe
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Función para validar archivos permitidos
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Ruta de registro
# Ruta para el registro de usuarios
import requests


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Recibir los datos del formulario
        username = request.form['username']
        password = request.form['password']
        role_id = request.form['role_id']
        area_id = request.form['area_id']

        # Datos obtenidos desde la API de RENIEC (ya recibidos desde la vista)
        nombres = request.form['nombres']
        apellido_paterno = request.form['apellido_paterno']
        apellido_materno = request.form['apellido_materno']

        # Hash de la contraseña
        password_hash = generate_password_hash(password)

        # Insertar datos del usuario en la base de datos
        try:
            cursor = db.cursor()
            cursor.execute(
                """INSERT INTO users (username, password_hash, role_id, area_id, estado, nombres, apellido_paterno, apellido_materno) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (username, password_hash, role_id, area_id, 0, nombres, apellido_paterno, apellido_materno)
            )
            db.commit()
            flash("Registro exitoso. Tu cuenta está pendiente de aprobación.", "success")
            return redirect(url_for('usuarios'))
        except Exception as e:
            db.rollback()
            flash(f"Error al registrar usuario: {str(e)}", "danger")

    # Obtener roles y áreas desde la base de datos
    cursor = db.cursor()
    cursor.execute("SELECT id, nombre FROM roles")
    roles = cursor.fetchall()

    cursor.execute("SELECT id, nombre FROM areas")
    areas = cursor.fetchall()

    return render_template('register.html', roles=roles, areas=areas)


# Ruta para servir las imágenes subidas
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin/approve_users', methods=['GET', 'POST'])
@login_required
def approve_users():
    if current_user.role_id != 1:  # Solo el administrador puede aprobar
        flash("Acceso denegado.", "error")
        return redirect(url_for('inicio'))

    if request.method == 'POST':
        user_id = request.form['user_id']
        cursor.execute("UPDATE users SET estado = 1 WHERE id = %s", (user_id,))
        db.commit()
        flash("Usuario aprobado exitosamente.", "success")

    cursor.execute("SELECT id, username, estado FROM users WHERE estado = 0")
    unapproved_users = cursor.fetchall()
    return render_template('approve_users.html', users=unapproved_users)

@app.before_request
def restrict_unapproved_users():
    if current_user.is_authenticated and current_user.estado == 0:  # Aquí verificamos con 0
        if request.endpoint not in ['logout', 'login', 'register']:
            flash("Tu cuenta está pendiente de aprobación.", "warning")
            return redirect(url_for('logout'))

def requires_roles(*roles):
    """
    Decorador para restringir el acceso a usuarios con roles específicos.
    :param roles: Lista de roles permitidos.
    """
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Verificar si el usuario está autenticado
            if not current_user.is_authenticated:
                return abort(403)  # Prohibir acceso si no está autenticado

            # Verificar si el rol del usuario está en la lista de roles permitidos
            if current_user.role_id not in roles:
                return abort(403)  # Prohibir acceso si el rol no es permitido
            
            # Si cumple con los roles, ejecutar la función
            return f(*args, **kwargs)
        return wrapped
    return wrapper

@app.route('/admin', methods=['GET'])
@login_required
def admin_page():
    # Obtener el número de página de la solicitud (por defecto la página 1)
    page = request.args.get('page', 1, type=int)
    per_page = 30  # Mostrar 10 noticias por página

    # Obtener el término de búsqueda
    search_query = request.args.get('search', '')

    # Si hay una búsqueda, filtrar las noticias por el título
    if search_query:
        cursor.execute(
            "SELECT * FROM noticias WHERE title LIKE %s LIMIT %s OFFSET %s",
            ('%' + search_query + '%', per_page, (page - 1) * per_page)
        )
    else:
        cursor.execute("SELECT * FROM noticias LIMIT %s OFFSET %s", (per_page, (page - 1) * per_page))

    noticias = cursor.fetchall()

    # Obtener el número total de noticias
    if search_query:
        cursor.execute("SELECT COUNT(*) FROM noticias WHERE title LIKE %s", ('%' + search_query + '%',))
    else:
        cursor.execute("SELECT COUNT(*) FROM noticias")
    
    total_noticias = cursor.fetchone()[0]

    # Calcular el número total de páginas
    total_pages = (total_noticias // per_page) + (1 if total_noticias % per_page > 0 else 0)

    # Incluir los datos del gráfico de noticias por día
    df = get_noticias_por_dia()  # Llamar a la función que obtenga las noticias por día

    # Verificar si la solicitud es AJAX y retornar solo la tabla
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return render_template('tabla_noticias.html', noticias=noticias, page=page, total_pages=total_pages)

    # Si no es AJAX, renderizar la página completa
    return render_template(
        'admin.html',
        noticias=noticias,
        page=page,
        total_pages=total_pages,
        search_query=search_query,
        noticias_por_dia=df
    )
    


@app.route('/registro')
def registro():
    return render_template('registrocombustible.html')
    
@app.route('/')
def inicio():
    return render_template('login.html')

@app.route('/index')
def home():
    return render_template('index.html')


# 🟢 Mostrar lista de roles
@app.route('/roles')
def roles():
    cursor = db.cursor()
    cursor.execute("SELECT id, nombre, descripcion FROM roles")
    roles = cursor.fetchall()
    return render_template('manage_roles.html', roles=roles)


# 🔵 Crear un nuevo rol
@app.route('/roles/crear', methods=['POST'])
def crear_rol():
    nombre = request.form['nombre']
    descripcion = request.form['descripcion']

    try:
        cursor = db.cursor()
        cursor.execute("INSERT INTO roles (nombre, descripcion) VALUES (%s, %s)", (nombre, descripcion))
        db.commit()
        flash('Rol creado con éxito.', 'success')
    except Exception as e:
        db.rollback()
        flash(f'Error al crear el rol: {str(e)}', 'danger')

    return redirect(url_for('roles'))


# 🟡 Actualizar un rol existente
@app.route('/roles/editar/<int:role_id>', methods=['POST'])
def editar_rol(role_id):
    nombre = request.form['nombre']
    descripcion = request.form['descripcion']

    try:
        cursor = db.cursor()
        cursor.execute("""
            UPDATE roles 
            SET nombre = %s, descripcion = %s 
            WHERE id = %s
        """, (nombre, descripcion, role_id))
        db.commit()

        flash('Rol actualizado con éxito.', 'success')
    except Exception as e:
        db.rollback()
        flash(f'Error al actualizar el rol: {str(e)}', 'danger')

    return redirect(url_for('roles'))


# 🔴 Eliminar un rol
@app.route('/roles/eliminar/<int:role_id>', methods=['POST'])
def eliminar_rol(role_id):
    try:
        cursor = db.cursor()
        cursor.execute("DELETE FROM roles WHERE id = %s", (role_id,))
        db.commit()

        flash('Rol eliminado con éxito.', 'success')
    except Exception as e:
        db.rollback()
        flash(f'Error al eliminar el rol: {str(e)}', 'danger')

    return redirect(url_for('roles'))

#Usuarios

@app.route('/usuarios')
def usuarios():
    cursor = db.cursor()
    # Consulta de usuarios
    cursor.execute("""
        SELECT u.id, u.username, u.nombres, u.apellido_paterno, u.apellido_materno, 
            u.role_id, u.area_id, u.estado, r.nombre AS rol_nombre, a.nombre AS area_nombre
        FROM users u
        JOIN roles r ON u.role_id = r.id
        JOIN areas a ON u.area_id = a.id
        """)
    usuarios = cursor.fetchall()

    # Consulta de roles
    cursor.execute("SELECT id, nombre FROM roles")
    roles = cursor.fetchall()

    # Consulta de áreas
    cursor.execute("SELECT id, nombre FROM areas")
    areas = cursor.fetchall()

    return render_template('users.html', usuarios=usuarios, roles=roles, areas=areas)



@app.route('/actualizar_usuario', methods=['POST'])
def actualizar_usuario():
    user_id = request.form['user_id']
    username = request.form['username']
    nombres = request.form['nombres']
    apellido_paterno = request.form['apellido_paterno']
    apellido_materno = request.form['apellido_materno']
    rol_id = request.form['rol']
    area_id = request.form['area']

    cursor = db.cursor()
    cursor.execute("""
        UPDATE users 
        SET username = %s, nombres = %s, apellido_paterno = %s, apellido_materno = %s,
            role_id = %s, area_id = %s
        WHERE id = %s
    """, (username, nombres, apellido_paterno, apellido_materno, rol_id, area_id, user_id))
    db.commit()

    return redirect(url_for('usuarios'))



@app.route('/cambiar_estado_usuario', methods=['POST'])
def cambiar_estado_usuario():
    user_id = request.form.get('user_id')
    nuevo_estado = request.form.get('nuevo_estado')

    cursor.execute("UPDATE users SET estado = %s WHERE id = %s", (nuevo_estado, user_id))
    db.commit()

    flash('Estado actualizado con éxito.', 'success')
    return redirect(url_for('usuarios'))






@app.route('/eliminar_usuario', methods=['POST'])
def eliminar_usuario():
    if request.method == 'POST':
        user_id = request.form.get('user_id')

        # Actualiza el estado a 0 (desactivado)
        query = "UPDATE usuarios SET estado = 0 WHERE id = ?"
        cursor = db.cursor()
        cursor.execute(query, (user_id,))
        db.commit()
        cursor.close()

        flash('Usuario desactivado correctamente.', 'success')
        return redirect(url_for('usuarios'))
   
   
    
#areas

@app.route('/areas', methods=['GET'])
def areas():
    cursor = db.cursor()
    cursor.execute("SELECT id, nombre, descripcion, jefe_area FROM areas")
    areas = cursor.fetchall()
    return render_template('areas.html', areas=areas)

# Crear área
@app.route('/areas/crear', methods=['POST'])
def crear_area():
    nombre = request.form['nombre']
    descripcion = request.form['descripcion']
    jefe_area = request.form['jefe_area']

    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO areas (nombre, descripcion, jefe_area) 
        VALUES (%s, %s, %s)
    """, (nombre, descripcion, jefe_area))
    db.commit()

    flash('Área creada con éxito.', 'success')
    return redirect(url_for('areas'))

# Editar área
@app.route('/areas/editar/<int:area_id>', methods=['POST'])
def editar_area(area_id):
    nombre = request.form['nombre']
    descripcion = request.form['descripcion']
    jefe_area = request.form['jefe_area']

    cursor = db.cursor()
    cursor.execute("""
        UPDATE areas 
        SET nombre = %s, descripcion = %s, jefe_area = %s 
        WHERE id = %s
    """, (nombre, descripcion, jefe_area, area_id))
    db.commit()

    flash('Área actualizada con éxito.', 'success')
    return redirect(url_for('areas'))


# Eliminar área
@app.route('/areas/eliminar/<int:area_id>', methods=['POST'])
def eliminar_area(area_id):
    cursor = db.cursor()
    cursor.execute("DELETE FROM areas WHERE id = %s", (area_id,))
    db.commit()

    flash('Área eliminada con éxito.', 'success')
    return redirect(url_for('areas'))




#reservas

# Ruta para listar las reservas
@app.route('/listar_reservas')
def listar_reservas():
    cursor = db.cursor()

    cursor.execute("""
        SELECT r.id, a.nombre AS area_nombre, r.mes, r.year, 
            r.cantidad_total, r.cantidad_disponible, r.area_id
        FROM reservas_combustible r
        JOIN areas a ON r.area_id = a.id
        ORDER BY r.id DESC
    """)
        
    reservas = cursor.fetchall()

    cursor.execute("SELECT id, nombre FROM areas")
    areas = cursor.fetchall()

    cursor.close()
    return render_template('reserva_combustible.html', reservas=reservas, areas=areas)


@app.route('/reservas/crear', methods=['POST'])
def crear_reserva():
    area_id = request.form.get('area_id')
    mes = request.form.get('mes')
    year = request.form.get('year')
    cantidad_total = request.form.get('cantidad_total')

    if not all([area_id, mes, year, cantidad_total]):
        flash('Todos los campos son obligatorios.', 'error')
        return redirect(url_for('listar_reservas'))

    # Asegurar que cantidad_disponible es igual a cantidad_total
    cantidad_disponible = cantidad_total

    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO reservas_combustible (area_id, mes, year, cantidad_total, cantidad_disponible, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
    ''', (area_id, mes, year, cantidad_total, cantidad_disponible))
    db.commit()
    flash('Reserva creada exitosamente.', 'success')
    return redirect(url_for('listar_reservas'))


@app.route('/reservas/editar/<int:id>', methods=['POST'])
def editar_reserva(id):
    area_id = request.form['area_id']
    mes = request.form['mes']
    year = request.form['year']
    cantidad_total = request.form['cantidad_total']
    cantidad_disponible = request.form['cantidad_disponible']

    cursor = db.cursor()
    updated_at = datetime.now()

    cursor.execute("""
        UPDATE reservas_combustible
        SET area_id = %s, mes = %s, year = %s, cantidad_total = %s, cantidad_disponible = %s, updated_at = %s
        WHERE id = %s
    """, (area_id, mes, year, cantidad_total, cantidad_disponible, updated_at, id))

    db.commit()
    cursor.close()

    return redirect(url_for('listar_reservas'))

@app.route('/reservas/eliminar/<int:id>', methods=['POST'])
def eliminar_reserva(id):
    cursor = db.cursor()

    cursor.execute("DELETE FROM reservas_combustible WHERE id = %s", (id,))

    db.commit()
    cursor.close()

    return redirect(url_for('listar_reservas'))

#vehiculos

UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Crear la carpeta si no existe
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@app.route('/vehiculos')
def vehiculos():
    cursor = db.cursor(dictionary=True)

    # Obtener vehículos con área asociada
    cursor.execute("""
        SELECT v.id, v.modelo, v.marca, v.anio, v.numero_placa, v.capacidad, v.imagen_url, v.area_id, a.nombre AS area_nombre
        FROM vehiculos v
        INNER JOIN areas a ON v.area_id = a.id
    """)
    vehiculos = cursor.fetchall()

    # Obtener todas las áreas para el formulario
    cursor.execute("SELECT id, nombre FROM areas")
    areas = cursor.fetchall()

    cursor.close()

    return render_template('vehiculos.html', vehiculos=vehiculos, areas=areas)

# Ruta para crear un vehículo
@app.route('/vehiculos/crear', methods=['POST'])
def crear_vehiculo():
    cursor = db.cursor()

    area_id = request.form['area_id']
    numero_placa = request.form['numero_placa']
    modelo = request.form['modelo']
    marca = request.form['marca']
    capacidad = request.form['capacidad']
    anio = request.form['anio']
    imagen = request.files.get('imagen')

    imagen_url = None
    if imagen and allowed_file(imagen.filename):
        filename = secure_filename(imagen.filename)
        imagen_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        imagen.save(imagen_path)
        imagen_url = filename

    try:
        query = """
            INSERT INTO vehiculos (area_id, numero_placa, modelo, marca, capacidad, anio, imagen_url) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (area_id, numero_placa, modelo, marca, capacidad, anio, imagen_url))
        db.commit()
        flash('Vehículo creado con éxito', 'success')
    except Exception as e:
        db.rollback()
        flash(f'Error al crear el vehículo: {str(e)}', 'danger')

    cursor.close()
    return redirect(url_for('vehiculos'))

# Ruta para editar un vehículo
@app.route('/vehiculos/editar/<int:id>', methods=['POST'])
def editar_vehiculo(id):
    cursor = db.cursor()

    area_id = request.form['area_id']
    numero_placa = request.form['numero_placa']
    modelo = request.form['modelo']
    marca = request.form['marca']
    capacidad = request.form['capacidad']
    anio = request.form['anio']
    imagen = request.files.get('imagen')

    try:
        if imagen and allowed_file(imagen.filename):
            filename = secure_filename(imagen.filename)
            imagen_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            imagen.save(imagen_path)
            imagen_url = filename

            query = """
                UPDATE vehiculos 
                SET area_id=%s, numero_placa=%s, modelo=%s, marca=%s, capacidad=%s, anio=%s, imagen_url=%s 
                WHERE id=%s
            """
            cursor.execute(query, (area_id, numero_placa, modelo, marca, capacidad, anio, imagen_url, id))
        else:
            query = """
                UPDATE vehiculos 
                SET area_id=%s, numero_placa=%s, modelo=%s, marca=%s, capacidad=%s, anio=%s
                WHERE id=%s
            """
            cursor.execute(query, (area_id, numero_placa, modelo, marca, capacidad, anio, id))

        db.commit()
        flash('Vehículo actualizado con éxito', 'success')
    except Exception as e:
        db.rollback()
        flash(f'Error al actualizar el vehículo: {str(e)}', 'danger')

    cursor.close()
    return redirect(url_for('vehiculos'))

# Ruta para eliminar un vehículo
@app.route('/vehiculos/eliminar/<int:id>', methods=['POST'])
def eliminar_vehiculo(id):
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM vehiculos WHERE id = %s", (id,))
        db.commit()
        flash('Vehículo eliminado con éxito', 'success')
    except Exception as e:
        db.rollback()
        flash(f'Error al eliminar el vehículo: {str(e)}', 'danger')

    cursor.close()
    return redirect(url_for('vehiculos'))



#registros

UPLOAD_FOLDER = 'static/uploads/registros'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'pdf'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def guardar_documento(documento):
    if documento and allowed_file(documento.filename):
        filename = secure_filename(documento.filename)
        documento_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        documento.save(documento_path)
        return filename
    return None


#registros
app.config['UPLOAD_FOLDER'] = 'static/uploads/registros'  # Carpeta donde se guardarán los archivos
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'jpg', 'jpeg', 'png', 'docx'}  # Extensiones permitidas


# Función para verificar si el archivo tiene una extensión permitida
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/formulario_combustible', methods=['GET'])
@login_required
def formulario_combustible():
    cursor = db.cursor(dictionary=True)

    # Obtener el área del usuario logueado
    cursor.execute("SELECT area_id FROM users WHERE id = %s", (current_user.id,))
    usuario = cursor.fetchone()
    area_id = usuario['area_id'] if usuario else None
    
    # Obtener vehículos
    cursor.execute("SELECT id, modelo FROM vehiculos")
    vehiculos = cursor.fetchall()

    # Obtener reservas con cantidad disponible
    cursor.execute("""
        SELECT id, cantidad_disponible, orden_servicio 
        FROM reservas_combustible 
        WHERE cantidad_disponible > 0
    """)
    reservas = cursor.fetchall()

    cursor.close()

    return render_template('registrocombustible.html', area_id=area_id, vehiculos=vehiculos, reservas=reservas)


@app.route('/registrar_combustible', methods=['POST'])
@login_required
def registrar_combustible():
    cursor = db.cursor(dictionary=True)

    # Obtener datos del formulario
    vehiculo_id = request.form['vehiculo_id']
    cantidad_solicitada = float(request.form['cantidad'])
    comentario = request.form['comentario']
    documento_path = None

    # Manejo del archivo
    if 'documento_path' in request.files:
        file = request.files['documento_path']
        if file.filename != '':
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            documento_path = f'static/uploads/registros/{filename}'

    # Obtener reservas seleccionadas y ordenarlas por cantidad disponible (de menor a mayor)
    reservas_seleccionadas = request.form.getlist('reservas')
    
    if not reservas_seleccionadas:
        flash("Error: Debes seleccionar al menos una reserva.", "error")
        return redirect(url_for('formulario_combustible'))

    # Formatear correctamente la consulta SQL para evitar errores
    format_strings = ','.join(['%s'] * len(reservas_seleccionadas))
    
    cursor.execute(f"""
        SELECT id, cantidad_disponible 
        FROM reservas_combustible 
        WHERE id IN ({format_strings})
        ORDER BY cantidad_disponible ASC
    """, tuple(reservas_seleccionadas))
    
    reservas = cursor.fetchall()

    cantidad_restante = cantidad_solicitada
    registros_reserva = []  # Para guardar lo que se va a registrar en la tabla intermedia

    for reserva in reservas:
        if cantidad_restante <= 0:
            break  # Ya se ha cubierto la cantidad solicitada

        reserva_id = reserva['id']
        cantidad_disponible = float(reserva['cantidad_disponible'])

        # Determinar cuánto tomar de esta reserva
        cantidad_a_usar = min(cantidad_restante, cantidad_disponible)
        cantidad_restante -= cantidad_a_usar

        # Guardar en la tabla intermedia
        registros_reserva.append((reserva_id, cantidad_a_usar))

        # Actualizar cantidad disponible en la base de datos
        cursor.execute("""
            UPDATE reservas_combustible 
            SET cantidad_disponible = cantidad_disponible - %s 
            WHERE id = %s
        """, (cantidad_a_usar, reserva_id))

    # Si aún queda cantidad sin cubrir, mostrar error
    if cantidad_restante > 0:
        flash("Error: No hay suficiente combustible disponible en las reservas seleccionadas.", "error")
        return redirect(url_for('formulario_combustible'))

    # Insertar registro en `registros_combustible`
    cursor.execute("""
        INSERT INTO registros_combustible (user_id, area_id, vehiculo_id, cantidad, comentario, documento_path, fecha_creacion, fecha_actualizacion)
        VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW())
    """, (current_user.id, current_user.area_id, vehiculo_id, cantidad_solicitada, comentario, documento_path))
    
    registro_combustible_id = cursor.lastrowid  # Obtener el ID del registro insertado

    # Insertar detalles en la tabla intermedia
    for reserva_id, cantidad_usada in registros_reserva:
        cursor.execute("""
            INSERT INTO registro_reservas (registro_id, reserva_id, cantidad_usada)
            VALUES (%s, %s, %s)
        """, (registro_combustible_id, reserva_id, cantidad_usada))

    db.commit()
    cursor.close()
    
    flash('Registro de combustible creado exitosamente', 'success')
    return redirect(url_for('formulario_combustible'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
    # app.run(debug=True)
