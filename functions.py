## This File contains all the functions used in the main file

from OTXv2 import *
from pandas import json_normalize
from dotenv import load_dotenv
import IndicatorTypes
import sqlite3
import random  
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
def get_pulses(query,limit=10):
    # Get pulses from OTX
    pulses=[]
    one_year_ago = datetime.now() - timedelta(days=365)
    timestamp = one_year_ago.strftime('%Y-%m-%dT%H:%M:%SZ')
    pulses = otx_object.getsince( timestamp, limit=10000, max_page=10, max_items=1000)
    df=json_normalize(pulses)
    filtered_dataframe = df[df['tags'].apply(lambda x: query in x)]
    for each in df['tags']:
        print(each)
    filtered_dataframe.reset_index(drop=True, inplace=True)
    flattened_data = []
    for index, row in filtered_dataframe.iterrows():
        flattened_row = {
            'id': row['id'],
            'Name': row['name'],
            'Author_name': row['author_name'],
            'modified': pd.to_datetime(row['modified']).strftime('%Y-%m-%d %H:%M'),
            'created': pd.to_datetime(row['created']).strftime('%Y-%m-%d %H:%M'),
            'revision': row['revision'],
        }
        flattened_data.append(flattened_row)
    return flattened_data
def get_pulse_detail(pulse_id):
    # Get pulse details from OTX
    pulse_details = otx_object.get_pulse_details(pulse_id)
    return pulse_details
def get_pulse_indicators(pulse_id):
    # Get pulse indicators from OTX
    indicators = otx_object.get_pulse_indicators(pulse_id)
    return indicators
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
    if indicator_type=='URI':
        return URI
    if indicator_type=='FileHash-MD5':
        return FILE_HASH_MD5
    if indicator_type=='FileHash-SHA1':
        return FILE_HASH_SHA1
    if indicator_type=='FileHash-SHA256':
        return FILE_HASH_SHA256
    if indicator_type=='FileHash-PEHASH':
        return FILE_HASH_PEHASH
    if indicator_type=='FileHash-IMPHASH':
        return FILE_HASH_IMPHASH
    if indicator_type=='CIDR':
        return CIDR
    if indicator_type=='FilePath':
        return FILE_PATH
    if indicator_type=='Mutex':
        return MUTEX
    if indicator_type=='CVE':
        return CVE
    if indicator_type=='YARA':
        return YARA
    if indicator_type=='IPv4':
        return IPv4
    if indicator_type=='IPv6':
        return IPv6
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
    indicators = otx_object.get_all_indicators(indicator_types=indicator_type, modified_since=modified_date,limit=5,max_items=10)
    
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


# Function to generate a randomized exploit entry
def generate_random_exploit():
    authors = [
        'Lance Biggerstaff', 'CANVAS', 'Metasploit', 'ExploitHub', 'Zero Day Initiative',
        'CyberSecOps', 'RedTeam', 'HackerOne', 'EthicalHacks', 'SecurityLab', 'ExploitMon'
    ]
    cve_ids = [
        'CVE-2021-4034', 'CVE-2022-1234', 'CVE-2023-5678', 'CVE-2024-9101',
        'CVE-2020-6789', 'CVE-2019-4567', 'CVE-2022-8765', 'CVE-2020-7654',
        'CVE-2018-2345', 'CVE-2017-8923', 'CVE-2016-1111'
    ]
    names = [
        'PolicyKit-1 0.105-31 - Privilege Escalation', 'linux_pkexec_argc', 'Remote Code Execution Exploit',
        'Buffer Overflow Vulnerability', 'Unauthorized Access Exploit', 'SQL Injection Attack Vector',
        'Heap Overflow Vulnerability', 'Command Injection Exploit', 'Directory Traversal Exploit',
        'Cross-Site Scripting Vulnerability', 'Denial of Service Attack Vector', 'Privilege Escalation Attack'
    ]
    platforms = ['linux', 'windows', 'macos', 'android', 'ios', 'unix', 'network', 'embedded', 'cloud', 'container']
    types = ['local', 'remote', 'network', 'physical', 'logical', 'cloud']
    ports = [22, 80, 443, 3306, 8080, 3389, 21, 23, 445, 53, 137, 138, 139, '']  # Common ports and empty option

    return {
        'author': random.choice(authors),
        'cve': random.choice(cve_ids),
        'date': datetime.strptime(f"{random.randint(2000, 2023)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}", "%Y-%m-%d").strftime("%Y-%m-%d"),
        'name': random.choice(names),
        'platform': random.choice(platforms),
        'port': str(random.choice(ports)),
        'type': random.choice(types),
        'url': f"https://example.com/exploit/{random.randint(10000, 99999)}"
    }

def get_random_geo_data():
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
        "city": random.choice(cities),
        "region": random.choice(regions),
        "continent_code": random.choice(continents),
        "country_code3": random.choice(country_codes3),
        "country_code2": random.choice(country_codes2),
        "subdivision": random.choice(subdivisions),
        "latitude": random.choice(latitudes),
        "longitude": random.choice(longitudes),
        "postal_code": random.choice(postal_codes),
        "accuracy_radius": random.choice(accuracy_radii),
        "country_code": random.choice(country_codes),
        "country_name": random.choice(country_names),
        "dma_code": random.choice(dma_codes),
        "charset": random.choice(charsets),
        "area_code": random.choice(area_codes),
        "flag_title": random.choice(flag_titles)
    }





