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
from xhtml2pdf import pisa

# Importación de funciones y configuración de base de datos desde `database.py`
from database import cursor, db

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'


# Configuración de Flask-Login

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"

class User(UserMixin):
    def __init__(self, id, username, password_hash, role_id, estado, area_id, nombres, apellido_paterno, apellido_materno, area_nombre, rol_nombre):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role_id = role_id
        self.estado = estado
        self.area_id = area_id  # ID del área
        self.nombres = nombres
        self.apellido_paterno = apellido_paterno
        self.apellido_materno = apellido_materno
        self.area_nombre = area_nombre  # Nombre del área
        self.rol_nombre = rol_nombre 
        
    @staticmethod
    def get_user_by_username(username):
        cursor.execute("""
            SELECT u.id, u.username, u.password_hash, u.role_id, u.estado, u.area_id, 
                   COALESCE(u.nombres, ''), COALESCE(u.apellido_paterno, ''), COALESCE(u.apellido_materno, ''), 
                   COALESCE(a.nombre, 'No asignado'), 
                   COALESCE(r.nombre, 'Sin rol')  -- Se agrega el nombre del rol
            FROM users u
            LEFT JOIN areas a ON u.area_id = a.id
            LEFT JOIN roles r ON u.role_id = r.id  -- Unimos la tabla de roles
            WHERE u.username = %s
        """, (username,))
        
        user_data = cursor.fetchone()
        
        if user_data:
            return User(*user_data)  # Pasa todos los datos correctamente
        return None



@staticmethod
def get_user_by_id(user_id):
    cursor.execute("""
        SELECT u.id, u.username, u.password_hash, u.role_id, u.estado, u.area_id, 
               COALESCE(u.nombres, ''), COALESCE(u.apellido_paterno, ''), COALESCE(u.apellido_materno, ''), 
               COALESCE(a.nombre, 'No asignado')
        FROM users u
        LEFT JOIN areas a ON u.area_id = a.id
        WHERE u.id = %s
    """, (user_id,))
    
    user_data = cursor.fetchone()

    if user_data:
        return User(*user_data)  # ✅ Ahora pasa los 10 valores correctos
    return None


from mysql.connector import Error


@login_manager.user_loader
def load_user(user_id):
    cursor = None  # ✅ Inicializa la variable antes del bloque try
    try:
        # 1. Reconectar si la conexión no está activa
        if not db.is_connected():
            db.reconnect(attempts=3, delay=1)

        # 2. Consumir todos los resultados no leídos si existen
        while db.unread_result:
            db.consume_results()

        # 3. Crear un nuevo cursor y ejecutar la consulta
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT u.id, u.username, u.password_hash, u.role_id, u.estado, u.area_id, 
                   COALESCE(u.nombres, '') AS nombres, 
                   COALESCE(u.apellido_paterno, '') AS apellido_paterno, 
                   COALESCE(u.apellido_materno, '') AS apellido_materno, 
                   COALESCE(a.nombre, 'No asignado') AS area_nombre, 
                   COALESCE(r.nombre, 'Sin rol') AS rol_nombre
            FROM users u
            LEFT JOIN areas a ON u.area_id = a.id
            LEFT JOIN roles r ON u.role_id = r.id
            WHERE u.id = %s
        """, (user_id,))

        # 4. Obtener los datos del usuario
        user_data = cursor.fetchone()

        # 5. Devolver el objeto User si existe
        if user_data:
            return User(**user_data)

    except Error as e:
        print(f"Error en load_user: {e}")

    finally:
        # ✅ Solo cerramos el cursor si se creó correctamente
        if cursor is not None:
            cursor.close()

    return None


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

import os

import requests
from werkzeug.utils import secure_filename


@app.route('/register', methods=['GET', 'POST'])
@login_required
@requires_roles(1)
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
@login_required
@requires_roles(1)
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



@app.route('/registro')
@login_required
@requires_roles(1)
def registro():
    return render_template('registrocombustible.html')
    
@app.route('/')
def inicio():
    return render_template('login.html')

@app.route('/index')
@login_required
def home():
    # Consultas para contar registros en cada tabla
    cursor.execute('SELECT COUNT(*) FROM registros_combustible')
    total_registros = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM vehiculos')
    total_vehiculos = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM reservas_combustible')
    total_reservas = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM users')
    total_usuarios = cursor.fetchone()[0]
    
    # total de registros
    cursor.execute('SELECT COUNT(*) FROM registros_combustible')
    total_registros = cursor.fetchone()[0] or 1


    cursor.execute('''
        SELECT a.nombre AS area_nombre, COUNT(r.id) AS total_registros
        FROM registros_combustible r
        JOIN areas a ON r.area_id = a.id
        GROUP BY a.nombre
    ''')
    registros_por_area = cursor.fetchall()

    registros_con_porcentaje = [
        (area, registros, round((registros / total_registros) * 100, 2))
        for area, registros in registros_por_area
    ]
    
    
    #consumo
    cursor.execute('SELECT SUM(cantidad) FROM registros_combustible')
    consumo_total = cursor.fetchone()[0] or 1

    cursor.execute('''
        SELECT a.nombre AS area_nombre, SUM(r.cantidad) AS total_consumido
        FROM registros_combustible r
        JOIN areas a ON r.area_id = a.id
        GROUP BY a.nombre
    ''')
    consumo_por_area = cursor.fetchall()

    consumo_con_porcentaje = [
        (area, cantidad, round((cantidad / consumo_total) * 100, 2))
        for area, cantidad in consumo_por_area
    ]

    return render_template('index.html', 
                           total_registros=total_registros, 
                           total_vehiculos=total_vehiculos, 
                           total_reservas=total_reservas, 
                           total_usuarios=total_usuarios,
                           registros_por_area=registros_por_area,
                           consumo_por_area=consumo_por_area,
                           consumo_con_porcentaje=consumo_con_porcentaje,
                           registros_con_porcentaje=registros_con_porcentaje)
    
    
@app.route('/reportes', methods=['GET'])
@login_required
def detalles_consumo():
    area_filtro = request.args.get('area', '')

    cursor = db.cursor()

    # Configurar el idioma de los nombres de los meses a español
    cursor.execute("SET lc_time_names = 'es_ES'")

    query = '''
    SELECT a.nombre AS area,
           u.nombres AS usuario,
           CONCAT(v.modelo, ' - ', v.numero_placa) AS vehiculo,
           MONTHNAME(rc.fecha_actualizacion) AS mes,
           rc.cantidad,
           rc.documento_path,
           rc.fecha_actualizacion,
           GROUP_CONCAT(r.orden_servicio) AS reservas
    FROM registros_combustible rc
    JOIN areas a ON rc.area_id = a.id
    JOIN users u ON rc.user_id = u.id
    JOIN vehiculos v ON rc.vehiculo_id = v.id
    LEFT JOIN registro_reservas rr ON rc.id = rr.registro_id
    LEFT JOIN reservas_combustible r ON rr.reserva_id = r.id
    '''

    # Verificar si el usuario es administrador
    es_admin = current_user.role_id == 1

    # Condiciones de filtrado
    condiciones = []
    parametros = []

    # Si no es admin, filtrar por el usuario actual
    if not es_admin:
        condiciones.append("rc.user_id = %s")
        parametros.append(current_user.id)

    # Si se proporciona un filtro de área (y es admin), aplicarlo
    if area_filtro and es_admin:
        condiciones.append("a.nombre = %s")
        parametros.append(area_filtro)

    # Agregar condiciones a la consulta si existen
    if condiciones:
        query += " WHERE " + " AND ".join(condiciones)

    query += " GROUP BY rc.id, a.nombre, u.nombres, v.modelo, v.numero_placa"
    query += " ORDER BY rc.fecha_actualizacion DESC"

    # Ejecutar la consulta con los parámetros
    cursor.execute(query, tuple(parametros))
    detalles_consumo = cursor.fetchall()

    # Obtener las áreas para el filtro (solo si es admin)
    areas = []
    if es_admin:
        cursor.execute('SELECT nombre FROM areas')
        areas = [area[0] for area in cursor.fetchall()]

    return render_template('reportes.html', detalles_consumo=detalles_consumo, areas=areas, area_filtro=area_filtro, es_admin=es_admin)


from datetime import datetime
from io import BytesIO


@app.route('/reportes/pdf', methods=['GET'])
@login_required
def exportar_pdf():
    area_filtro = request.args.get('area', '')

    cursor = db.cursor()
    cursor.execute("SET lc_time_names = 'es_ES'")

    query = '''
    SELECT a.nombre AS area,
           u.nombres AS usuario,
           CONCAT(v.modelo, ' - ', v.numero_placa) AS vehiculo,
           MONTHNAME(rc.fecha_actualizacion) AS mes,
           rc.cantidad,
           rc.documento_path,
           rc.fecha_actualizacion,
           GROUP_CONCAT(r.orden_servicio) AS reservas
    FROM registros_combustible rc
    JOIN areas a ON rc.area_id = a.id
    JOIN users u ON rc.user_id = u.id
    JOIN vehiculos v ON rc.vehiculo_id = v.id
    LEFT JOIN registro_reservas rr ON rc.id = rr.registro_id
    LEFT JOIN reservas_combustible r ON rr.reserva_id = r.id
    '''

    es_admin = current_user.role_id == 1

    condiciones = []
    parametros = []

    if not es_admin:
        condiciones.append("rc.user_id = %s")
        parametros.append(current_user.id)

    if area_filtro and es_admin:
        condiciones.append("a.nombre = %s")
        parametros.append(area_filtro)

    if condiciones:
        query += " WHERE " + " AND ".join(condiciones)

    query += " GROUP BY rc.id, a.nombre, u.nombres, v.modelo, v.numero_placa"
    query += " ORDER BY rc.fecha_actualizacion DESC"

    cursor.execute(query, tuple(parametros))
    detalles_consumo = cursor.fetchall()

    # Generar el PDF
    pdf = BytesIO()
    html = render_template('reportes_pdf.html', detalles_consumo=detalles_consumo, fecha_actual=datetime.now())
    pisa.CreatePDF(BytesIO(html.encode('utf-8')), pdf)

    pdf.seek(0)
    return Response(pdf, content_type='application/pdf',
                    headers={"Content-Disposition": "inline; filename=reportes.pdf"})



from datetime import datetime


def get_month_name(mes):
    meses = [
        "Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio",
        "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre"
    ]
    return meses[mes - 1] if 1 <= mes <= 12 else "Mes Desconocido"

@app.route('/graficos/cantidad_mes_actual', methods=['GET'])
@login_required
def cantidad_mes_actual():
    try:
        # Obtener el mes y año actual
        mes_actual = datetime.now().month
        año_actual = datetime.now().year

        # Consulta para obtener los datos con nombre del área y orden de servicio
        query = """
            SELECT r.orden_servicio, a.nombre AS area_nombre, r.cantidad_total, r.cantidad_disponible, r.mes
            FROM reservas_combustible r
            JOIN areas a ON r.area_id = a.id
            WHERE r.mes = %s AND r.year = %s
        """
        cursor.execute(query, (mes_actual, año_actual))
        resultados = cursor.fetchall()

        # Formatear los resultados como lista de objetos
        data = [
            {
                "orden_servicio": row[0],
                "area_nombre": row[1],
                "cantidad_total": float(row[2]),
                "cantidad_disponible": float(row[3]),
                "mes": get_month_name(row[4])
            }
            for row in resultados
        ]

        return jsonify(data)

    except Exception as e:
        print(f"Error en /graficos/cantidad_mes_actual: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500
    
# Mostrar lista de roles
@app.route('/roles')
@login_required
@requires_roles(1)
def roles():
    cursor = db.cursor()
    cursor.execute("SELECT id, nombre, descripcion FROM roles")
    roles = cursor.fetchall()
    return render_template('manage_roles.html', roles=roles)


# 🔵 Crear un nuevo rol
@app.route('/roles/crear', methods=['POST'])
@login_required
@requires_roles(1)
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


# Actualizar un rol existente
@app.route('/roles/editar/<int:role_id>', methods=['POST'])
@login_required
@requires_roles(1)
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


# Eliminar un rol
@app.route('/roles/eliminar/<int:role_id>', methods=['POST'])
@login_required
@requires_roles(1)
def eliminar_rol(role_id):
    try:
        if not db.is_connected():
            db.reconnect(attempts=3, delay=1)  # Asegura la conexión
        
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
@login_required
@requires_roles(1)
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
@login_required
@requires_roles(1)
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
@login_required
@requires_roles(1)
def cambiar_estado_usuario():
    user_id = request.form.get('user_id')
    nuevo_estado = request.form.get('nuevo_estado')

    cursor.execute("UPDATE users SET estado = %s WHERE id = %s", (nuevo_estado, user_id))
    db.commit()

    flash('Estado actualizado con éxito.', 'success')
    return redirect(url_for('usuarios'))


@app.route('/eliminar_usuario', methods=['POST'])
@login_required
@requires_roles(1)
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
@login_required
@requires_roles(1)
def areas():
    cursor = db.cursor()
    cursor.execute("SELECT id, nombre, descripcion, jefe_area, estado FROM areas")
    areas = cursor.fetchall()
    return render_template('areas.html', areas=areas)

# Crear área
@app.route('/areas/crear', methods=['POST'])
@login_required
@requires_roles(1)
def crear_area():
    nombre = request.form['nombre']
    descripcion = request.form['descripcion']
    jefe_area = request.form['jefe_area']

    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO areas (nombre, descripcion, jefe_area, estado) 
        VALUES (%s, %s, %s, %s)
    """, (nombre, descripcion, jefe_area, 1))
    db.commit()

    flash('Área creada con éxito.', 'success')
    return redirect(url_for('areas'))

# Editar área
@app.route('/areas/editar/<int:area_id>', methods=['POST'])
@login_required
@requires_roles(1)
def editar_area(area_id):
    nombre = request.form['nombre']
    descripcion = request.form['descripcion']
    jefe_area = request.form['jefe_area']
    estado = request.form.get('estado', 1)

    cursor = db.cursor()
    cursor.execute("""
        UPDATE areas 
        SET nombre = %s, descripcion = %s, jefe_area = %s, estado = %s
        WHERE id = %s
    """, (nombre, descripcion, jefe_area, estado, area_id))
    db.commit()

    flash('Área actualizada con éxito.', 'success')
    return redirect(url_for('areas'))


# Eliminar área (Inactivar si tiene relaciones)
@app.route('/areas/eliminar/<int:area_id>', methods=['POST'])
@login_required
@requires_roles(1)
def eliminar_area(area_id):
    try:
        cursor = db.cursor()

        # Verificar si el área tiene relaciones con otras tablas
        cursor.execute("""
            SELECT 
                (SELECT COUNT(*) FROM vehiculos WHERE area_id = %s) +
                (SELECT COUNT(*) FROM reservas_combustible WHERE area_id = %s) +
                (SELECT COUNT(*) FROM registros_combustible WHERE area_id = %s) +
                (SELECT COUNT(*) FROM users WHERE area_id = %s)
        """, (area_id, area_id, area_id, area_id))
        
        relaciones = cursor.fetchone()[0]

        if relaciones > 0:
            # Si hay relaciones, solo inactivar el área
            cursor.execute("UPDATE areas SET estado = 0 WHERE id = %s", (area_id,))
            mensaje = "Área inactivada correctamente."
        else:
            # Si no hay relaciones, eliminar el área definitivamente
            cursor.execute("DELETE FROM areas WHERE id = %s", (area_id,))
            mensaje = "Área eliminada correctamente."

        db.commit()
        cursor.close()

        return jsonify({'success': True, 'message': mensaje})

    except Exception as e:
        db.rollback()  # 🔄 Revertir cambios en caso de error
        print(f"Error al eliminar el área: {e}")
        return jsonify({'success': False, 'message': 'Error interno del servidor'}), 500


#reservas

# Ruta para listar las reservas
@app.route('/listar_reservas')
@login_required
@requires_roles(1)
def listar_reservas():
    cursor = db.cursor()

    cursor.execute("""
        SELECT r.id, a.nombre AS area_nombre, r.orden_servicio, r.mes, r.year, 
            r.cantidad_total, r.cantidad_disponible, r.area_id, r.estado
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
@login_required
@requires_roles(1)
def crear_reserva():
    area_id = request.form.get('area_id')
    orden_servicio = request.form.get('orden_servicio')
    mes = request.form.get('mes')
    year = request.form.get('year')
    cantidad_total = request.form.get('cantidad_total')

    if not all([area_id, orden_servicio, mes, year, cantidad_total]):
        flash('Todos los campos son obligatorios.', 'error')
        return redirect(url_for('listar_reservas'))

    # Asegurar que cantidad_disponible es igual a cantidad_total
    cantidad_disponible = cantidad_total

    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO reservas_combustible (area_id, orden_servicio, mes, year, cantidad_total, cantidad_disponible, estado, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, 1, NOW(), NOW())
    ''', (area_id, orden_servicio, mes, year, cantidad_total, cantidad_disponible))
    db.commit()
    flash('Reserva creada exitosamente.', 'success')
    return redirect(url_for('listar_reservas'))


@app.route('/reservas/editar/<int:id>', methods=['POST'])
@login_required
@requires_roles(1)
def editar_reserva(id):
    area_id = request.form['area_id']
    orden_servicio = request.form['orden_servicio']
    mes = request.form['mes']
    year = request.form['year']
    cantidad_total = request.form['cantidad_total']
    cantidad_disponible = request.form['cantidad_disponible']
    estado = request.form.get('estado', 1)

    cursor = db.cursor()
    updated_at = datetime.now()

    cursor.execute("""
        UPDATE reservas_combustible
        SET area_id = %s, orden_servicio = %s, mes = %s, year = %s, cantidad_total = %s, cantidad_disponible = %s, estado = %s, updated_at = %s
        WHERE id = %s
    """, (area_id, orden_servicio, mes, year, cantidad_total, cantidad_disponible, estado, updated_at, id))

    db.commit()
    cursor.close()

    return redirect(url_for('listar_reservas'))

@app.route('/reservas/eliminar/<int:id>', methods=['POST'])
@login_required
@requires_roles(1)
def eliminar_reserva(id):
    try:
        cursor = db.cursor()

        # Verificar si hay registros relacionados
        cursor.execute("SELECT COUNT(*) FROM registro_reservas WHERE reserva_id = %s", (id,))
        registros_relacionados = cursor.fetchone()[0]

        if registros_relacionados > 0:
            # Si hay registros relacionados, solo inactivar
            cursor.execute("UPDATE reservas_combustible SET estado = 0 WHERE id = %s", (id,))
            mensaje = "Reserva inactivada correctamente."
        else:
            # Eliminar si no hay registros relacionados
            cursor.execute("DELETE FROM reservas_combustible WHERE id = %s", (id,))
            mensaje = "Reserva eliminada permanentemente."

        db.commit()
        cursor.close()
        return jsonify({'success': True, 'message': mensaje})

    except Exception as e:
        print(f"Error al eliminar la reserva: {e}")
        return jsonify({'success': False, 'message': 'Error interno del servidor'}), 500




#vehiculos

# Ruta para obtener todos los vehículos
@app.route('/vehiculos', methods=['GET'])
def vehiculos():
    sql = """
        SELECT v.id, v.numero_placa, v.modelo, v.marca, v.capacidad, v.anio, 
               v.estado, v.area_id, a.nombre AS area
        FROM vehiculos v
        JOIN areas a ON v.area_id = a.id
        ORDER BY v.id DESC  -- Orden descendente
    """
    cursor.execute(sql)
    columnas = [col[0] for col in cursor.description]  # Obtener nombres de columnas
    vehiculos = [dict(zip(columnas, row)) for row in cursor.fetchall()]

    # Obtener todas las áreas para el select
    cursor.execute("SELECT id, nombre FROM areas")
    areas = cursor.fetchall()

    return render_template('vehiculos.html', vehiculos=vehiculos, areas=areas)


# Ruta para agregar un vehículo
@app.route('/vehiculos/add', methods=['POST'])
def add_vehiculo():
    numero_placa = request.form['numero_placa']
    modelo = request.form['modelo']
    marca = request.form['marca']
    capacidad = request.form['capacidad']
    anio = request.form['anio']
    area_id = request.form['area_id']  
    estado = request.form.get('estado', 1)  # 1 por defecto (Activo)

    sql = """
        INSERT INTO vehiculos (area_id, numero_placa, modelo, marca, capacidad, anio, estado)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """
    cursor.execute(sql, (area_id, numero_placa, modelo, marca, capacidad, anio, estado))
    db.commit()
    flash('Vehículo agregado exitosamente', 'success')
    return redirect(url_for('vehiculos'))

# Ruta para editar un vehículo
@app.route('/vehiculos/edit/<int:id>', methods=['GET', 'POST'])
def edit_vehiculo(id):
    if request.method == 'POST':
        numero_placa = request.form['numero_placa']
        modelo = request.form['modelo']
        marca = request.form['marca']
        capacidad = request.form['capacidad']
        anio = request.form['anio']
        area_id = request.form['area_id']
        estado = request.form.get('estado', 1)  

        sql = """
            UPDATE vehiculos 
            SET area_id = %s, numero_placa = %s, modelo = %s, marca = %s, 
                capacidad = %s, anio = %s, estado = %s 
            WHERE id = %s
        """
        cursor.execute(sql, (area_id, numero_placa, modelo, marca, capacidad, anio, estado, id))
        db.commit()
        flash('Vehículo actualizado correctamente', 'success')
        return redirect(url_for('vehiculos'))
    
    # Si es GET, obtener datos del vehículo
    cursor.execute("SELECT * FROM vehiculos WHERE id = %s", (id,))
    vehiculo = cursor.fetchone()

    # Obtener todas las áreas para el select
    cursor.execute("SELECT id, nombre FROM areas")
    areas = cursor.fetchall()

    return render_template('editar_vehiculo.html', vehiculo=vehiculo, areas=areas)

# Ruta para eliminar un vehículo
@app.route('/vehiculos/delete/<int:id>', methods=['POST'])
def delete_vehiculo(id):
    # Verificar si el vehículo tiene registros en 'registros_combustible'
    cursor.execute("""
        SELECT COUNT(*) FROM registros_combustible WHERE vehiculo_id = %s
    """, (id,))
    registros_relacionados = cursor.fetchone()[0]

    if registros_relacionados > 0:
        # Si tiene registros relacionados, solo cambiar el estado a inactivo
        cursor.execute("UPDATE vehiculos SET estado = 0 WHERE id = %s", (id,))
        db.commit()
        return jsonify({'success': True, 'message': 'Vehículo inactivado correctamente', 'inactivated': True})
    else:
        # Si no tiene registros relacionados, eliminarlo completamente
        cursor.execute("DELETE FROM vehiculos WHERE id = %s", (id,))
        db.commit()
    return jsonify({'success': True, 'message': 'Vehículo eliminado permanentemente', 'inactivated': False})





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
@requires_roles(1,2) 
def formulario_combustible():
    cursor = db.cursor(dictionary=True)

    # Obtener el área del usuario logueado
    cursor.execute("SELECT area_id FROM users WHERE id = %s", (current_user.id,))
    usuario = cursor.fetchone()
    area_id = usuario['area_id'] if usuario else None
    
    # Obtener vehículos
    cursor.execute("SELECT id, modelo FROM vehiculos")
    vehiculos = cursor.fetchall()

    mes_actual = datetime.now().month
    #reservas
    cursor.execute("""
        SELECT r.id, r.cantidad_disponible, r.orden_servicio, a.nombre AS nombre_area, r.mes
        FROM reservas_combustible r
        JOIN areas a ON r.area_id = a.id
        WHERE r.mes = %s
    """, (mes_actual,))

    reservas = cursor.fetchall()
    

    return render_template('registrocombustible.html', area_id=area_id, vehiculos=vehiculos, reservas=reservas)


@app.route('/registrar_combustible', methods=['POST'])
@login_required
@requires_roles(1,2) 
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
