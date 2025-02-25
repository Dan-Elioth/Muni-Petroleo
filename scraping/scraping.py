import re
from datetime import datetime, timedelta

import mysql.connector
import pandas as pd
import requests
from bs4 import BeautifulSoup

from database import insert_noticia

# Configuración de conexión a la base de datos
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="noticias_db",
    port="3308"
)
cursor = db.cursor()

# Función para verificar si una noticia ya existe en la base de datos usando la URL
def noticia_existe(url):
    query = "SELECT COUNT(*) FROM noticias WHERE url = %s"
    cursor.execute(query, (url,))
    result = cursor.fetchone()
    return result[0] > 0



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
        # Solo devolver la fecha en formato 'YYYY-MM-DD'
        return fecha.strftime('%Y-%m-%d')
    # Si no se encuentra una coincidencia, devolver la fecha actual sin hora
    return ahora.strftime('%Y-%m-%d')

def scrape_noticia_detallada_diariosinfronteras(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    full_content = soup.find('div', class_='post-content-bd').get_text(separator="\n").strip()
    return full_content

def scrape_diariosinfronteras_por_categoria(categoria_url, categoria_nombre):
    response = requests.get(categoria_url)
    soup = BeautifulSoup(response.content, 'html.parser')
    articles = soup.find_all('div', class_='layout-wrap')
    for article in articles:
        title = article.find('h3', class_='entry-title').text.strip()
        fecha_relativa = article.find('div', class_='post-date-bd').find('span').text.strip()
        date = convertir_fecha_relativa(fecha_relativa)
        content = article.find('div', class_='post-excerpt').text.strip()
        image = article.find('img')['src']
        url = article.find('a')['href']
        full_content = scrape_noticia_detallada_diariosinfronteras(url)
        insert_noticia(title, date, content, image, url, categoria_nombre, full_content)

def scrape_categorias_diariosinfronteras():
    url = "https://diariosinfronteras.com.pe/category/tacna/"
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    categorias = []
    menu = soup.find('ul', id='menu-primary')
    if menu:
        for li in menu.find_all('li'):
            a_tag = li.find('a')
            span_tag = a_tag.find('span', class_='menu-label') if a_tag else None
            if a_tag and span_tag:
                categoria = span_tag.text.strip()
                url_categoria = a_tag['href']
                categorias.append({'nombre': categoria, 'url': url_categoria})
    return categorias

def scrape_todas_las_categorias():
    categorias = scrape_categorias_diariosinfronteras()
    
    # Iterar sobre cada categoría y extraer las noticias
    for categoria in categorias:
        categoria_url = categoria['url']
        categoria_nombre = categoria['nombre']
        scrape_diariosinfronteras_por_categoria(categoria_url, categoria_nombre)
