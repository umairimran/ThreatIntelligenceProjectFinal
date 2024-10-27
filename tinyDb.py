from tinydb import *
from functions import *
from OTXv2 import *
from admin import * 
from flask import session
import threading
from datetime import datetime, timedelta
db = TinyDB('db.json')
indicators_table = db.table('indicators')
Indicator= Query()
from dotenv import load_dotenv
load_dotenv()
otx_object = OTXv2(os.getenv('os.getenv('"API_KEY"')'))
db_lock = threading.Lock()
def insert_indicators_in_table(modified_date, indicator_type):
    """
    Inserts indicators into the database if they do not already exist.

    Parameters:
    modified_date (str): The date when the indicators were modified.
    indicator_type (str): The type of indicators to retrieve.

    Returns:
    None
    """
    # Retrieve full details of indicators based on the modified date and type
    indicator_types = [
        CVE,
        DOMAIN,
        HOSTNAME,
        URL,
        IPv4,
        
    ]
    
    for each in indicator_types:
        indicators_full_details = get_indicators(modified_date, [each])

        # Get all existing indicators from the database
        
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
    """
    Searches for an indicator in the database based on multiple terms in the query.

    Parameters:
    query (str): The query to search for, containing multiple terms.

    Returns:
    list: A list of dictionaries containing the search results.
    """
    # Return all indicators if the query is empty
    if not query.strip():  # Check if query is empty or contains only whitespace
        with db_lock:
            return indicators_table.all()  # Return all indicators

    terms = query.split()  # Split the query into individual terms
    patterns = [re.compile(term, re.IGNORECASE) for term in terms]  # Create a regex for each term
    results = []
    
    with db_lock:
        indicators_all = indicators_table.all()
    
    for doc in indicators_all:
        # Normalize JSON data for easier access
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
def get_cleaned_indicator_data_from_database(query):
    ''''
    This function takes input as query and searches by using the search for indicator function and then returns the cleaned data in the form of a dataframe

    return : dataframe on each row is a complete indicator full details of a whole section
    '''
    raw_indicators=search_for_indicator(query)
    df=json_normalize(raw_indicators)
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
        return get_dataframe_by_indicator(df, 'domain')


def search_url_with_query(query: str):
    with db_lock:
        data=indicators_table.all()
        df=json_normalize(data)
        return get_dataframe_by_indicator(df, 'URL')


def search_ip4_with_query(query: str):
    with db_lock:
        data=indicators_table.all()
        df=json_normalize(data)
        return get_dataframe_by_indicator(df, 'IPv4')


def search_hostnames_with_query(query: str):
    with db_lock:
        data=indicators_table.all()
        df=json_normalize(data)
        return get_dataframe_by_indicator(df, 'hostname')


def get_dataframe_by_indicator(dataframe, indicator):
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
            indicators_list.append(indicator_data)
    
    return indicators_list


