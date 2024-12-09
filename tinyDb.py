from tinydb import *
from functions import *
from OTXv2 import *
import stanza


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
# Download the English model
stanza.download('en')

# Initialize the pipeline
nlp = stanza.Pipeline('en')
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

# Define predefined phrases
PREDEFINED_PHRASES = ["windows 11", "sql server", "apache server", "sql injection"]

def get_cleaned_indicator_data_from_database(query):
    '''
    This function takes input as query and searches by using the search_for_indicator function 
    and then returns the cleaned data in the form of a dataframe.
    
    return: dataframe where each row is a complete indicator with an additional 'category' column
    '''
    # Dictionary to store the individual terms from the query
    query_keywords = {}
    
    # Split the query into individual words and create a dictionary of keywords
    for index, each in enumerate(query.split()):
        query_keywords[each] = each
    
    print("Query Keywords:", query_keywords)
    
    # Get raw indicators using the search_for_indicator function
    raw_indicators = search_for_indicator(query)
    
    # Normalize raw indicators into a dataframe
    df = json_normalize(raw_indicators)
    
    # Add a new column 'category' initialized to None or empty
    df['category'] = None
    
    # Step 1: First, check for matches with predefined phrases
    for phrase in PREDEFINED_PHRASES:
        for idx, row in df.iterrows():
            description = str(row.get('general.description', ''))
            products = str(row.get('general.products', ''))
            
            # Check if any predefined phrase exists in description or products
            if phrase.lower() in description.lower() or phrase.lower() in products.lower():
                # If a match is found, assign the category based on the predefined phrase
                if pd.isnull(df.at[idx, 'category']):
                    df.at[idx, 'category'] = phrase
                else:
                    # Optionally, append the category if there are multiple matches
                    df.at[idx, 'category'] = str(df.at[idx, 'category']) + ', ' + phrase
    
    # Step 2: Now check for individual query terms
    for each in query_keywords:
        for idx, row in df.iterrows():
            description = str(row.get('general.description', ''))
            products = str(row.get('general.products', ''))
            
            # Check if the term exists in description or products field
            if each.lower() in description.lower() or each.lower() in products.lower():
                # If a match is found, assign the category based on the query term
                if pd.isnull(df.at[idx, 'category']):
                    df.at[idx, 'category'] = query_keywords[each]
                else:
                    # Optionally, append the category if there are multiple matches
                    df.at[idx, 'category'] = str(df.at[idx, 'category']) + ', ' + query_keywords[each]
    
    # Clean up categories by removing duplicates and unnecessary commas
    df['category'] = df['category'].apply(lambda x: ', '.join(sorted(set(str(x).split(', ')))) if isinstance(x, str) else x)
    
    # Optionally, further clean up by removing unwanted terms or formatting
    # For example, remove specific terms from category:
    # df['category'] = df['category'].apply(lambda x: x.replace('windows', 'Windows') if isinstance(x, str) else x)
    
    print("Cleaned DataFrame Categories:", df['category'])
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


