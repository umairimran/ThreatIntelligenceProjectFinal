## This File contains all the functions used in the main file

from OTXv2 import *
from pandas import json_normalize
from dotenv import load_dotenv
import IndicatorTypes
import sqlite3
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
    """
    Fetches and returns a list of full indicator details based on the modified data.

    Args:
        modified_data (str): The date from which indicators should be fetched (ISO format).
        indicator_type (str, optional): The specific type of indicator to filter by (e.g., 'CVE', 'IP', etc.).
                                        Defaults to None, which retrieves all indicator types.
    
    Returns:
        list: A list of dictionaries containing full indicator details.
              If no indicators are found, an empty list is returned.
    
    Raises:
        ValueError: If the `modified_data` is not in the correct format or if the API response fails.
    """
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


