## This File contains all the functions used in the main file

from OTXv2 import *
from pandas import json_normalize
from dotenv import load_dotenv
import IndicatorTypes
import sqlite3
from services.IndicatorTypes import get_values
import pandas as pd
from flask import flash
from IndicatorTypes import *
import pandas
import numpy as np
from datetime import datetime, timedelta

load_dotenv()
## load the environment variables
api =  os.getenv('API_KEY')
otx_object = OTXv2(api)


def safe_get(value):
    try:
        return int(value[0]) if isinstance(value, (list, np.ndarray)) else value
    except (IndexError, ValueError):
        return None  # or return '' if you prefer an empty string
    

def get_indicator_type(indicator_type):
    print(indicator_type)
    if indicator_type=='domain':
        return DOMAIN
    if indicator_type=='hostname':
        return HOSTNAME
    if indicator_type=='email':
        return EMAIL
    if indicator_type=='URL':
        return URL
    if indicator_type=='CVE':
        return CVE
    if indicator_type=='IPv4':
        return IPv4
    else:
        return None
    

def get_passive_dns_list_of_indicator(filtered_dataframe):
    flattened_data = []
    for index, row in filtered_dataframe.iterrows():
        flattened_row = {
            'address': row['address'],
            'first': row['first'],
            'last': row['last'],
            'hostname': row['hostname'],
            'record_type': row['record_type'],
            'indicator_link': row['indicator_link'],
            'flag_url': row['flag_url'],
            'flag_title': row['flag_title'],
            'asset_type': row['asset_type'],
            'asn': row['asn'],
        }
        flattened_data.append(flattened_row)
    
    return flattened_data


def get_urls_list_of_indicator(df):
    flattened_data = []
    
    for index, row in df.iterrows():
        flattened_row = {
            'url': row['url'],
            'date': row['date'],
            'domain': row['domain'],
            'hostname': row['hostname'],
            'httpcode': row['httpcode'],
            'gsb': row['gsb'],
            'encoded': row['encoded'],
            'result_urlworker_ip': row['result.urlworker.ip'],
            'result_urlworker_http_code': row['result.urlworker.http_code'],
            'result_safebrowsing_matches': row['result.safebrowsing.matches'],
        }
        flattened_data.append(flattened_row)
    
    return flattened_data

def get_indicators(modified_date, indicator_type):
# Initialize the list to hold full indicator details
    indicators_full_details_list = []
        # Fetch all indicators modified since the provided date
    indicators = otx_object.get_all_indicators(indicator_types=indicator_type, modified_since=modified_date)
    
    indicator_list=list(indicators)
    for each in indicator_list:
        indicators_full_details_list.append(otx_object.get_indicator_details_full(indicator_type=get_indicator_type(each['type']), indicator=each['indicator']))
    return indicators_full_details_list

DATABASE='users.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn
def create_users_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            designation TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
def signup(username, email, password, designation):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            INSERT INTO users (username, email, password, designation)
            VALUES (?, ?, ?, ?)
        ''', (username, email, password))  # Password should be hashed in production

        conn.commit()
        user_id = cursor.lastrowid  # Get the user ID of the newly created user
        flash('Account created successfully!', 'success')
        return user_id  # Return the new user ID
    except sqlite3.IntegrityError:
        flash('Email already exists. Please use a different email.', 'danger')
        return None
    finally:
        conn.close()

def login(email, password):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users WHERE email=?', (email,))
    user = cursor.fetchone()

    if user and user['password'] == password:  # Validate password (consider hashing)
        return user  # Return user information for session management
    else:
        flash('Invalid credentials. Please try again.', 'danger')
        return None
# app/functiona.py

def create_software_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS software (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            software_name TEXT NOT NULL,
            vulnerability TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

def get_geo_data():
    # Example realistic data
    cities = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix"]
    regions = ["NY", "CA", "IL", "TX", "AZ"]
    continents = ["NA", "NA", "NA", "NA", "NA"]
    country_codes3 = ["USA", "USA", "USA", "USA", "USA"]
    country_codes2 = ["US", "US", "US", "US", "US"]
    subdivisions = ["NY", "CA", "IL", "TX", "AZ"]
    latitudes = [40.7128, 34.0522, 41.8781, 29.7604, 33.4484]
    longitudes = [-74.0060, -118.2437, -87.6298, -95.3698, -112.0740]
    postal_codes = ["10001", "90001", "60601", "77001", "85001"]
    accuracy_radii = [5, 10, 15, 20, 25]
    country_codes = ["US", "US", "US", "US", "US"]
    country_names = ["United States", "United States", "United States", "United States", "United States"]
    dma_codes = [501, 502, 503, 504, 505]
    charsets = ["UTF-8", "ISO-8859-1", "UTF-16", "ASCII", "ISO-8859-15"]
    area_codes = ["212", "213", "312", "713", "602"]
    flag_titles = ["Flag of the USA", "Flag of the USA", "Flag of the USA", "Flag of the USA", "Flag of the USA"]

    return {
            "city": get_values(cities),
            "region": get_values(regions),
            "continent_code": get_values(continents),
            "country_code3": get_values(country_codes3),
            "country_code2": get_values(country_codes2),
            "subdivision": get_values(subdivisions),
            "latitude": get_values(latitudes),
            "longitude": get_values(longitudes),
            "postal_code": get_values(postal_codes),
            "accuracy_radius": get_values(accuracy_radii),
            "country_code": get_values(country_codes),
            "country_name": get_values(country_names),
            "dma_code": get_values(dma_codes),
            "charset": get_values(charsets),
            "area_code": get_values(area_codes),
            "flag_title": get_values(flag_titles)
        }




