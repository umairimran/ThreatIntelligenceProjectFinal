from tinydb import *
from functions import *
from OTXv2 import *



from admin import * 
from flask import session
from db_lock import *
from flask import Flask, jsonify, Response, request
from multiprocessing import Process
import time
import json
from datetime import datetime, timedelta
db = TinyDB('db.json')
indicators_table = db.table('indicators')
Indicator= Query()
from dotenv import load_dotenv
load_dotenv()
otx_object = OTXv2(os.getenv('os.getenv('"API_KEY"')'))

def insert_indicators_in_table(modified_date, indicator_type):
    """
    Inserts indicators into the database if they do not already exist.

    Parameters
    modified_date (str): The date when the indicators were modified.
    indicator_type (str): The type of indicators to retrieve.

    Returns:
    None
    """
    # Retrieve full details of indicators based on the modified date and type
    indicator_types = [
       
    DOMAIN,
    HOSTNAME,
    URL,
   # IPv4,
    CVE 
    ]
    
    for each in indicator_types:
        indicators_full_details = get_indicators(modified_date, [each])

        # Get all existing indicators from the database
        with db_lock:
            found_indicators_in_database = indicators_table.all()
        indicators_found_in_database = []

            # Collect indicators that are currently in the database
        for each in found_indicators_in_database:
                try:
                    indicators_found_in_database.append(json_normalize(each)['general.base_indicator.indicator'][0])
                except (KeyError, IndexError) as e:
                    # Log the error or handle it accordingly, but continue processing
                    print(f"Error processing existing indicator: {e}")

            # Loop through the retrieved indicators to check for insertion
        for indicator in indicators_full_details:
                try:
                    ind = json_normalize(indicator)['general.base_indicator.indicator'][0]
                    
                    # Check if the indicator is already in the database
                    if ind not in indicators_found_in_database:
                        # Insert the new indicator into the database
                        
                        with db_lock:
                            indicators_table.insert(indicator)
                            print('Indicator inserted in database')
                            
                        
                    else:
                        # Indicate that the indicator already exists
                        print('Indicator already exists in database')
                except (KeyError, IndexError) as e:
                    # Log the error or handle it accordingly, but continue processing
                    print(f"Error processing indicator: {e}")

def search_for_indicator(query):


    if not query.strip(): 
        with db_lock:
            return indicators_table.all()  

    terms = query.split()  
    patterns = [re.compile(term, re.IGNORECASE) for term in terms]  
    results = []
    
    with db_lock:
        indicators_all = indicators_table.all()
    
    for doc in indicators_all:
      
        df = json_normalize(doc)
        
        df[df['general.base_indicator.type'] == 'CVE']
        df=df.head(500)
     
        try:
            description = df['general.description'][0]
            products = df['general.products'][0]  # Assuming this is a list of product identifiers
        except KeyError:
            description = ''
            products = []

        # Check if any pattern matches either in the description or across products
        description_match = any(pattern.search(str(description)) for pattern in patterns)
        products_match = any(any(pattern.search(str(product)) for pattern in patterns) for product in products)

        if description_match or products_match:
            results.append(doc)

    return results


import pandas as pd
from pandas import json_normalize
import pandas as pd
from pandas import json_normalize
def get_formatted_query(query):
    # Step 1: Split the query into words
    query_words = query.split()
    cleaned_query_keywords = {}
    
    # Step 2: Iterate through words and look for numbers
    index = 0
    while index < len(query_words):
        current_word = query_words[index]
        
        # Check if the current word is followed by a number
        if index + 1 < len(query_words) and re.match(r'\d+', query_words[index + 1]):  # next word is a number
            combined_word = f"{current_word} {query_words[index + 1]}"
            cleaned_query_keywords[combined_word] = combined_word
            index += 2  # Skip the next word since it's part of the current combined word
        else:
            cleaned_query_keywords[current_word] = current_word
            index += 1
    
    print("Cleaned Query Keywords:", cleaned_query_keywords)
    return cleaned_query_keywords
# Define predefined phrases
PREDEFINED_PHRASES = ["windows 11", "sql server", "apache server", "sql injection"]

def get_cleaned_indicator_data_from_database(query):
    # Get the cleaned query keywords (the terms to look for)
    query_keywords = get_formatted_query(query)

    # Fetch raw indicators based on the query
    raw_indicators = search_for_indicator(query)

    # Normalize the raw data into a DataFrame
    df = json_normalize(raw_indicators)

    # Ensure the 'category' column exists, but we won't set it to None
    # Instead, we'll initialize it with empty strings if it doesn't already exist
    if 'category' not in df.columns:
        df['category'] = ''

    # Loop through each query term (keyword) and check if it appears in the description or products fields
    for each in query_keywords:
        for idx, row in df.iterrows():
            description = str(row.get('general.description', ''))
            products = str(row.get('general.products', ''))
            
            # Check if the query term exists in the description or products field
            if each.lower() in description.lower() or each.lower() in products.lower():
                # If the category already has some values, append the new one
                if df.at[idx, 'category']:
                    df.at[idx, 'category'] += ', ' + query_keywords[each]
                else:
                    # If the category is empty, set it to the first matching category term
                    df.at[idx, 'category'] = query_keywords[each]
    
    # After all the matching, clean up the 'category' column: remove duplicates, sort, and join
    df['category'] = df['category'].apply(
        lambda x: ', '.join(sorted(set(str(x).split(', ')))) if isinstance(x, str) else x
    )
    df = df[df['category'].str.strip().ne('')]
    return df
















def get_single_indicator_full_details(data):
    df=json_normalize(data)


def refresh(days):
    """
    Refreshes the database by removing all existing data.

    Parameters:
    None

    Returns:
    None
    """
    insert_indicators_in_table((datetime.now() - timedelta(days=days)).date(), 'IPv4')

def search_domain_with_query(query: str):
    with db_lock:
        data=indicators_table.all()
        df=json_normalize(data)
        df=df.sort_values(by='general.date_modified', ascending=False)
        return get_dataframe_by_indicator(df, 'domain',query)


def search_url_with_query(query: str):
    with db_lock:
        data=indicators_table.all()
        df=json_normalize(data)
        df=df.sort_values(by='general.date_modified', ascending=False)
    
        return get_dataframe_by_indicator(df, 'URL',query)


def search_ip4_with_query(query: str):
    with db_lock:
        data=indicators_table.all()
        df=json_normalize(data)
        df=df.sort_values(by='general.date_modified', ascending=False)
        df= get_dataframe_by_indicator(df, 'IPv4',query)
        
        return df


def search_hostnames_with_query(query: str):
    with db_lock:
        data=indicators_table.all()
        df=json_normalize(data)
        df=df.sort_values(by='general.date_modified', ascending=False)
        
        return get_dataframe_by_indicator(df, 'hostname',query)


def get_dataframe_by_indicator(dataframe, indicator, query=''):
    # Define the date one day ago
    one_day_ago = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    
    # Try sorting the dataframe, if it fails, handle the exception
    try:
        dataframe = dataframe.sort_values(by='general.date_modified', ascending=False)
    except Exception as e:
        print(f"Error sorting dataframe: {e}")

    indicators_list = []

    # Loop through the rows of the dataframe that match the indicator type
    for index, each in dataframe[dataframe['general.base_indicator.type'] == indicator].iterrows():
        # Extract tags for the current indicator
        tags = []
        try:
            # Normalize the 'general.pulse_info.pulses' and fetch the tags
            pulses_df = json_normalize(each['general.pulse_info.pulses'])
            
            tags =pulses_df['tags'].dropna().tolist()
          
        except Exception as e:
            print(f"Error retrieving tags: {e}")

        def get_value_or_random(field):
            try:
                # Attempt to get the value from the row
                value = each.get(field, '')
                # Return a random number if the value is NaN or empty
                return round(random.uniform(1, 10), 2) if pd.isna(value) or value == '' else value
            except Exception as e:
                print(f"Error retrieving value for field '{field}': {e}")
                return None  # Return None if there's an error

        # Create a dictionary for each indicator and append it to the list
        indicator_data = {
            'indicator': each.get('general.base_indicator.indicator', ''),
            'type': each.get('general.base_indicator.type', ''),
            'severity': get_value_or_random('general.cvssv2.severity'),
            'attackComplexity': get_value_or_random('general.cvssv3.cvssV3.attackComplexity'),
            'baseSeverity': get_value_or_random('general.cvssv3.cvssV3.baseSeverity'),
            'exploitabilityScore': get_value_or_random('general.cvssv3.exploitabilityScore'),
            'impactScore': get_value_or_random('general.cvssv3.impactScore'),
            'access_type': get_value_or_random('general.base_indicator.access_type'),
            'access_reason': get_value_or_random('general.base_indicator.access_reason'),
            'date_modified': pd.to_datetime(each.get('general.date_modified', datetime.now())).date(),
            'date_created': pd.to_datetime(each.get('general.date_created', datetime.now())).date(),
           
        }

        # Only add to the list if the required keys are present
        if indicator_data['indicator'] and indicator_data['type']:
            # If the query is not empty, check for matches in the tags
            if query and not any(query in tag for tag_list in tags for tag in tag_list):
                continue  # Skip this indicator if the query doesn't match any tags
            indicators_list.append(indicator_data)

    return indicators_list





def extract_tags_by_indicator(indicator):
    with db_lock:
        df = indicators_table.all()
        df = json_normalize(df)
        tags = [item['tags'] for item in json_normalize(df[df['general.base_indicator.type'] == indicator]['general.pulse_info.pulses'])[0].dropna()]
        
        # Flatten the list and remove duplicates
        unique_tags = list(set(tag for sublist in tags for tag in sublist))
    return unique_tags


