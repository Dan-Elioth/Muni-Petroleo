from datetime import datetime

import mysql.connector
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# Configuración de conexión a la base de datos
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="proyectpretroleo",
    port="3308"
)
cursor = db.cursor()

def cargar_datos(cursor):
    query = "SELECT id, title, content, source, diario, date FROM noticias"
    return pd.read_sql(query, con=cursor)

def obtener_recomendaciones(noticia_id, noticias_df, top_n=5):
    noticias_df['combined'] = noticias_df['title'] + " " + noticias_df['content']
    vectorizer = TfidfVectorizer(stop_words='spanish')
    tfidf_matrix = vectorizer.fit_transform(noticias_df['combined'])
    idx = noticias_df[noticias_df['id'] == noticia_id].index[0]
    cosine_sim = cosine_similarity(tfidf_matrix[idx], tfidf_matrix).flatten()
    similar_indices = cosine_sim.argsort()[-(top_n + 1):-1][::-1]
    return noticias_df.iloc[similar_indices][['id', 'title', 'source', 'diario', 'date']]

# Función para verificar si una noticia ya existe en la base de datos usando la URL
def noticia_existe(url):
    query = "SELECT COUNT(*) FROM noticias WHERE url = %s"
    cursor.execute(query, (url,))
    result = cursor.fetchone()
    return result[0] > 0

# Función para insertar o actualizar una noticia en la base de datos
# Función para insertar o actualizar una noticia en la base de datos, incluyendo la columna 'diario'
def insert_noticia(title, date, content, image, url, source, full_content, diario="Diario Sin Fronteras"):
    fecha_scraping = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if noticia_existe(url):
        print(f"Noticia encontrada: {title}. Se actualizará.")
        query = """
        UPDATE noticias 
        SET title = %s, date = %s, content = %s, image = %s, source = %s, full_content = %s, fecha_scraping = %s, diario = %s
        WHERE url = %s
        """
        values = (title, date, content, image, source, full_content, fecha_scraping, diario, url)
    else:
        print(f"Insertando noticia: {title}.")
        query = """
        INSERT INTO noticias (title, date, content, image, url, source, full_content, fecha_scraping, diario) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (title, date, content, image, url, source, full_content, fecha_scraping, diario)

    cursor.execute(query, values)
    db.commit()
    print(f"Operación completada para la noticia: {title}")



# Función para obtener el total de noticias según un rango de fechas
def get_noticias_count_by_date_range(start_date, end_date=None):
    query = "SELECT COUNT(*) FROM noticias WHERE DATE(date) >= %s"
    params = [start_date]
    if end_date:
        query += " AND DATE(date) <= %s"
        params.append(end_date)
    cursor.execute(query, params)
    result = cursor.fetchone()
    return result[0]

# Función para obtener el total de noticias por categoría
def get_total_noticias_por_categoria():
    query = "SELECT source, COUNT(*) FROM noticias GROUP BY source"
    cursor.execute(query)
    result = cursor.fetchall()
    return result

# Función para obtener todas las noticias
# En tu función que obtiene noticias, verifica que el id es numérico
def get_all_noticias():
    query = "SELECT * FROM noticias ORDER BY date DESC"
    cursor.execute(query)
    noticias = cursor.fetchall()
    # Filtrar solo noticias con identificadores numéricos
    noticias_filtradas = [noticia for noticia in noticias if isinstance(noticia[0], int)]
    return noticias_filtradas


# Función para obtener noticias filtradas por categoría
def get_noticias_por_categoria(categoria_nombre):
    query = "SELECT * FROM noticias WHERE source = %s ORDER BY date DESC"
    cursor.execute(query, (categoria_nombre,))
    return cursor.fetchall()

# Función para obtener el total de noticias según la fecha de scraping
def get_noticias_por_dia():
    query = """
    SELECT DATE(fecha_scraping) as scrape_date, COUNT(*) as total_noticias 
    FROM noticias 
    GROUP BY scrape_date 
    ORDER BY scrape_date DESC
    """
    cursor.execute(query)
    result = cursor.fetchall()
    df = pd.DataFrame(result, columns=['scrape_date', 'total_noticias'])
    return df

# Función para obtener el conteo de noticias por categoría específica
def get_noticias_conteo_por_categoria(categoria_nombre):
    query = "SELECT COUNT(*) FROM noticias WHERE source = %s"
    cursor.execute(query, (categoria_nombre,))
    result = cursor.fetchone()
    return result[0]

# Función para obtener todas las categorías disponibles
def get_categorias():
    query = "SELECT DISTINCT source FROM noticias"
    cursor.execute(query)
    result = cursor.fetchall()
    return [categoria[0] for categoria in result]

# Función para exportar noticias a un archivo CSV
def exportar_noticias_a_csv():
    query = "SELECT * FROM noticias"
    noticias_df = pd.read_sql(query, db)
    noticias_df.to_csv('noticias_exportadas.csv', index=False, encoding='utf-8')
    print("Noticias exportadas correctamente a 'noticias_exportadas.csv'.")


def obtener_noticias_del_dia():
    fecha_hoy = datetime.now().strftime('%Y-%m-%d')
    query = """
    SELECT * FROM noticias 
    WHERE DATE(date) = %s
    ORDER BY date DESC
    """
    cursor.execute(query, (fecha_hoy,))
    noticias = cursor.fetchall()
    total_noticias_dia = len(noticias)
    return noticias, total_noticias_dia


# ---------------------- Diario sin fronteras

def get_categorias_sin_fronteras():
    query = "SELECT DISTINCT source FROM noticias WHERE diario = %s"
    cursor.execute(query, ("Diario Sin Fronteras",))
    result = cursor.fetchall()
    return [categoria[0] for categoria in result]

def get_noticias_sin_fronteras():
    query = "SELECT * FROM noticias WHERE diario = %s ORDER BY date DESC"
    cursor.execute(query, ("Diario Sin Fronteras",))
    return cursor.fetchall()

def obtener_noticias_del_dia_sin_fronteras():
    fecha_hoy = datetime.now().strftime('%Y-%m-%d')
    query = "SELECT * FROM noticias WHERE DATE(date) = %s AND diario = %s ORDER BY date DESC"
    cursor.execute(query, (fecha_hoy, "Diario Sin Fronteras"))
    noticias = cursor.fetchall()
    total_noticias_dia = len(noticias)
    return noticias, total_noticias_dia

def get_conteo_noticias_por_categoria_sin_fronteras(categoria):
    query = "SELECT COUNT(*) FROM noticias WHERE source = %s AND diario = %s"
    cursor.execute(query, (categoria, "Diario Sin Fronteras"))
    result = cursor.fetchone()
    return result[0]

# ---------------fin

# -------- Diario Correo
def get_all_noticias_diario(diario_nombre):
    query = "SELECT * FROM noticias WHERE diario = %s ORDER BY date DESC"
    cursor.execute(query, (diario_nombre,))
    noticias = cursor.fetchall()
    return noticias

# Obtener categorías específicas para Diario Correo
def get_categorias_diario(diario_nombre):
    query = "SELECT DISTINCT source FROM noticias WHERE diario = %s"
    cursor.execute(query, (diario_nombre,))
    result = cursor.fetchall()
    return [categoria[0] for categoria in result]

# Contar noticias por categoría para Diario Correo
def get_noticias_conteo_por_categoria_diario(categoria_nombre, diario_nombre):
    query = "SELECT COUNT(*) FROM noticias WHERE source = %s AND diario = %s"
    cursor.execute(query, (categoria_nombre, diario_nombre))
    result = cursor.fetchone()
    return result[0]

# Obtener noticias del día solo de Diario Correo
def obtener_noticias_del_dia_diario(diario_nombre):
    fecha_hoy = datetime.now().strftime('%Y-%m-%d')
    query = "SELECT * FROM noticias WHERE DATE(date) = %s AND diario = %s ORDER BY date DESC"
    cursor.execute(query, (fecha_hoy, diario_nombre))
    noticias = cursor.fetchall()
    total_noticias_dia = len(noticias)
    return noticias, total_noticias_dia

# Exportar noticias a CSV solo para Diario Correo
def exportar_noticias_a_csv_diario(diario_nombre):
    query = "SELECT * FROM noticias WHERE diario = %s"
    noticias_df = pd.read_sql(query, db, params=(diario_nombre,))
    noticias_df.to_csv(f'noticias_{diario_nombre.lower().replace(" ", "_")}.csv', index=False, encoding='utf-8')
    print(f"Noticias exportadas correctamente a 'noticias_{diario_nombre.lower().replace(' ', '_')}.csv'.")

# -------------------Fin


# ------------ Diario el peruano --------
def get_all_noticias_peruano():
    query = "SELECT * FROM noticias WHERE diario = %s ORDER BY date DESC"
    cursor.execute(query, ("El Peruano",))
    noticias = cursor.fetchall()
    return noticias

# Obtener categorías específicas para El Peruano
def get_categorias_peruano():
    query = "SELECT DISTINCT source FROM noticias WHERE diario = %s"
    cursor.execute(query, ("El Peruano",))
    result = cursor.fetchall()
    return [categoria[0] for categoria in result]

# Contar noticias por categoría para El Peruano
def get_noticias_conteo_por_categoria_peruano(categoria_nombre):
    query = "SELECT COUNT(*) FROM noticias WHERE source = %s AND diario = %s"
    cursor.execute(query, (categoria_nombre, "El Peruano"))
    result = cursor.fetchone()
    return result[0]

# Obtener noticias del día solo de El Peruano
def obtener_noticias_del_dia_peruano():
    fecha_hoy = datetime.now().strftime('%Y-%m-%d')
    query = """
    SELECT * FROM noticias 
    WHERE diario = 'El Peruano' AND DATE(date) = %s
    ORDER BY date DESC
    """
    cursor.execute(query, (fecha_hoy,))
    noticias = cursor.fetchall()
    return noticias, len(noticias)  # Devuelve las noticias de hoy y el conteo

# Exportar noticias a CSV solo para El Peruano
def exportar_noticias_a_csv_peruano():
    query = "SELECT * FROM noticias WHERE diario = %s"
    noticias_df = pd.read_sql(query, db, params=("El Peruano",))
    noticias_df.to_csv('noticias_el_peruano.csv', index=False, encoding='utf-8')
    print("Noticias exportadas correctamente a 'noticias_el_peruano.csv'.")
    
# ------ fin ----