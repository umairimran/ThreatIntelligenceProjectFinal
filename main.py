from flask import Flask
from flask import request
from flask import redirect
from flask import render_template
import os
import time
import random
from collections import defaultdict
from flask import Flask
from threading import Thread, Event
from multiprocessing import Process, Event
from admin import *
from services.IndicatorTypes import get_values
from flask_caching import Cache
from flask import url_for,flash
from flask import Flask, render_template, request, redirect, flash, session
from flask import session
from functions import *
from tinyDb import *




app=Flask(__name__)
stop_event = Event()
# Flag to control session clearing
clear_session_flag = True
cache = Cache(app, config={'CACHE_TYPE': 'simple'})
app.secret_key = '123456789'




users = retrieve_users() 
@app.route('/login', methods=['GET', 'POST'])
def login():
    users = retrieve_users()  
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print("Username:",username)
        print("Password:",password)
        if username=='siteadmin' and password=='siteadmin':
            session['username'] = username
            return redirect(url_for('admin_page'))
        user_dict = {user[1]: {'password': user[2], 'email': user[3], 'system': user[4], 'service': user[5], 'indicator': user[6]} for user in users}
        if username in user_dict and user_dict[username]['password'] == password:
            session['username'] = username  
            session['system'] = user_dict[username]['system']
            session['service'] = user_dict[username]['service']
            session['indicator'] = user_dict[username]['indicator']
            flash('Login successful!', 'success')
            return redirect(url_for('search_indicators'))  
        else:
            flash('Invalid username or password. Please try again.', 'danger')
    return render_template('login.html') 




@app.route('/logout')
def logout():
    # Clear the session to log out the user
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login')) 




@app.route('/')
def index():
    global clear_session_flag
    if  clear_session_flag:
        session.clear()
        clear_session_flag=False
    if 'username' in session:  # Check if the user is logged in
        print("Logged in")

        return redirect(url_for('search_indicators'))  # Redirect to search_indicators if logged in
    else:
        return redirect(url_for('login'))  # Redirect to login if not logged in
    




@app.route('/cve', methods=['GET', 'POST'])
def cve_page():
    if request.method == 'POST':
        indicator_type=request.form['base_indicator_type']
        indicator=request.form['indicator']
        i = otx_object.get_indicator_details_full(indicator_type=get_indicator_type(indicator_type), indicator=indicator)
        df = json_normalize(i)
        def safe_get(column_name):
            return df[column_name][0] if column_name in df.columns else ''
        def get_value(column_name):
            values = {
                'general.cvssv2.acInsufInfo': get_values([True, False]),
                'general.cvssv2.cvssV2.accessComplexity': get_values(['LOW', 'MEDIUM', 'HIGH']),
                'general.cvssv2.cvssV2.accessVector': get_values(['LOCAL', 'ADJACENT_NETWORK', 'NETWORK']),
                'general.cvssv2.cvssV2.authentication': get_values(['NONE', 'SINGLE', 'MULTIPLE']),
                'general.cvssv2.cvssV2.availabilityImpact': get_values(['NONE', 'PARTIAL', 'COMPLETE']),
                'general.cvssv2.cvssV2.baseScore': round(random.uniform(0, 10), 1),
                'general.cvssv2.cvssV2.confidentialityImpact': get_values(['NONE', 'PARTIAL', 'COMPLETE']),
                'general.cvssv2.cvssV2.integrityImpact': get_values(['NONE', 'PARTIAL', 'COMPLETE']),
                'general.cvssv2.cvssV2.version': '2.0',
                'general.cvssv2.exploitabilityScore': round(random.uniform(0, 10), 1),
                'general.cvssv2.impactScore': round(random.uniform(0, 10), 1),
                'general.cvssv2.obtainAllPrivilege': get_values([True, False]),
                'general.cvssv2.obtainOtherPrivilege': get_values([True, False]),
                'general.cvssv2.obtainUserPrivilege': get_values([True, False]),
                'general.cvssv2.severity': get_values(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
                'general.cvssv2.userInteractionRequired': get_values([True, False]),
            }

            return values.get(column_name, '')
        general_sections = safe_get('general.sections')
        general_mitre_url = safe_get('general.mitre_url')
        general_nvd_url = safe_get('general.nvd_url')
        general_indicator = safe_get('general.indicator')
        general_type_title = safe_get('general.type_title')
        general_base_indicator_id = int(safe_get('general.base_indicator.id')) if safe_get('general.base_indicator.id') else 0
        general_base_indicator_type = safe_get('general.base_indicator.type')
        general_pulse_info_count = safe_get('general.pulse_info.count')
        general_pulse_info_pulses = safe_get('general.pulse_info.pulses')
        general_pulse_info_references = safe_get('general.pulse_info.references')
        general_pulse_info_related_alienvault_malware_families = safe_get('general.pulse_info.related.alienvault.malware_families')
        general_pulse_info_related_alienvault_industries = safe_get('general.pulse_info.related.alienvault.industries')
        general_pulse_info_related_other_adversary = safe_get('general.pulse_info.related.other.adversary')
        general_pulse_info_related_other_malware_families = safe_get('general.pulse_info.related.other.malware_families')
        general_pulse_info_related_other_industries = safe_get('general.pulse_info.related.other.industries')
        general_false_positive = safe_get('general.false_positive')
        general_cve = safe_get('general.cve')
        general_cvss_access_complexity = safe_get('general.cvss.Access-Complexity')
        general_cvss_access_vector = safe_get('general.cvss.Access-Vector')
        general_cvss_authentication = safe_get('general.cvss.Authentication')
        general_cvss_availability_impact = safe_get('general.cvss.Availability-Impact')
        general_cvss_score = safe_get('general.cvss.Score')
        general_cvss_confidentiality_impact = safe_get('general.cvss.Confidentiality-Impact')
        general_cvss_integrity_impact = safe_get('general.cvss.Integrity-Impact')
        general_cvss_vector_string = safe_get('general.cvss.vectorString')
        general_cvssv2_ac_insuf_info = get_value('general.cvssv2.acInsufInfo')
        general_cvssv2_access_complexity = get_value('general.cvssv2.cvssV2.accessComplexity')
        general_cvssv2_access_vector = get_value('general.cvssv2.cvssV2.accessVector')
        general_cvssv2_authentication = get_value('general.cvssv2.cvssV2.authentication')
        general_cvssv2_availability_impact = get_value('general.cvssv2.cvssV2.availabilityImpact')
        general_cvssv2_base_score = get_value('general.cvssv2.cvssV2.baseScore')
        general_cvssv2_confidentiality_impact = get_value('general.cvssv2.cvssV2.confidentialityImpact')
        general_cvssv2_integrity_impact = get_value('general.cvssv2.cvssV2.integrityImpact')
        general_cvssv2_version = get_value('general.cvssv2.cvssV2.version')
        general_cvssv2_exploitability_score = get_value('general.cvssv2.exploitabilityScore')
        general_cvssv2_impact_score = get_value('general.cvssv2.impactScore')
        general_cvssv2_obtain_all_privilege = get_value('general.cvssv2.obtainAllPrivilege')
        general_cvssv2_obtain_other_privilege = get_value('general.cvssv2.obtainOtherPrivilege')
        general_cvssv2_obtain_user_privilege = get_value('general.cvssv2.obtainUserPrivilege')
        general_cvssv2_severity = get_value('general.cvssv2.severity')
        general_cvssv2_user_interaction_required = get_value('general.cvssv2.userInteractionRequired')
        general_cvssv3_attack_complexity = safe_get('general.cvssv3.cvssV3.attackComplexity')
        general_cvssv3_attack_vector = safe_get('general.cvssv3.cvssV3.attackVector')
        general_cvssv3_availability_impact = safe_get('general.cvssv3.cvssV3.availabilityImpact')
        general_cvssv3_base_score = safe_get('general.cvssv3.cvssV3.baseScore')
        general_cvssv3_base_severity = safe_get('general.cvssv3.cvssV3.baseSeverity')
        general_cvssv3_confidentiality_impact = safe_get('general.cvssv3.cvssV3.confidentialityImpact')
        general_cvssv3_integrity_impact = safe_get('general.cvssv3.cvssV3.integrityImpact')
        general_cvssv3_privileges_required = safe_get('general.cvssv3.cvssV3.privilegesRequired')
        general_cvssv3_scope = safe_get('general.cvssv3.cvssV3.scope')
        general_cvssv3_user_interaction = safe_get('general.cvssv3.cvssV3.userInteraction')
        general_cvssv3_version = safe_get('general.cvssv3.cvssV3.version')
        general_cvssv3_exploitability_score = safe_get('general.cvssv3.exploitabilityScore')
        general_cvssv3_impact_score = safe_get('general.cvssv3.impactScore')
        general_configurations_cve_data_version = safe_get('general.configurations.CVE_data_version')
        df['general.configurations.nodes'][0]
        general_configurations_nodes=[]
        for cpe in df['general.configurations.nodes'][0]:
            general_configurations_nodes.append(cpe['cpe_match'])
        general_cwe = safe_get('general.cwe')
        general_products = safe_get('general.products')
        general_seen_wild = safe_get('general.seen_wild')
        general_references = safe_get('general.references')
        general_description = safe_get('general.description')
        general_date_modified = safe_get('general.date_modified')
        general_date_created = safe_get('general.date_created')
        general_exploits=[]
        try:
            general_exploits=df['general.exploits'][0]
        except:
            pass
        general_epss = safe_get('general.epss')
        return render_template('indicator_full_detail.html', 
                               user_logged_in=session['username'],
                               general_sections=general_sections,
                               general_mitre_url=general_mitre_url,
                               general_nvd_url=general_nvd_url,
                               general_indicator=general_indicator,
                               general_type_title=general_type_title,
                               general_base_indicator_id=general_base_indicator_id,
                               general_base_indicator_type=general_base_indicator_type,
                               general_pulse_info_count=general_pulse_info_count,
                               general_pulse_info_pulses=general_pulse_info_pulses,
                               general_pulse_info_references=general_pulse_info_references,
                               general_pulse_info_related_alienvault_malware_families=general_pulse_info_related_alienvault_malware_families,
                               general_pulse_info_related_alienvault_industries=general_pulse_info_related_alienvault_industries,
                               general_pulse_info_related_other_adversary=general_pulse_info_related_other_adversary,
                               general_pulse_info_related_other_malware_families=general_pulse_info_related_other_malware_families,
                               general_pulse_info_related_other_industries=general_pulse_info_related_other_industries,
                               general_false_positive=general_false_positive,
                               general_cve=general_cve,
                               general_cvss_access_complexity=general_cvss_access_complexity,
                               general_cvss_access_vector=general_cvss_access_vector,
                               general_cvss_authentication=general_cvss_authentication,
                               general_cvss_availability_impact=general_cvss_availability_impact,
                               general_cvss_score=general_cvss_score,
                               general_cvss_confidentiality_impact=general_cvss_confidentiality_impact,
                               general_cvss_integrity_impact=general_cvss_integrity_impact,
                               general_cvss_vector_string=general_cvss_vector_string,
                               general_cvssv2_ac_insuf_info=general_cvssv2_ac_insuf_info,
                               general_cvssv2_access_complexity=general_cvssv2_access_complexity,
                               general_cvssv2_access_vector=general_cvssv2_access_vector,
                               general_cvssv2_authentication=general_cvssv2_authentication,
                               general_cvssv2_availability_impact=general_cvssv2_availability_impact,
                               general_cvssv2_base_score=general_cvssv2_base_score,
                               general_cvssv2_confidentiality_impact=general_cvssv2_confidentiality_impact,
                               general_cvssv2_integrity_impact=general_cvssv2_integrity_impact,
                               general_cvssv2_version=general_cvssv2_version,
                               general_cvssv2_exploitability_score=general_cvssv2_exploitability_score,
                               general_cvssv2_impact_score=general_cvssv2_impact_score,
                               general_cvssv2_obtain_all_privilege=general_cvssv2_obtain_all_privilege,
                               general_cvssv2_obtain_other_privilege=general_cvssv2_obtain_other_privilege,
                               general_cvssv2_obtain_user_privilege=general_cvssv2_obtain_user_privilege,
                               general_cvssv2_severity=general_cvssv2_severity,
                               general_cvssv2_user_interaction_required=general_cvssv2_user_interaction_required,
                               general_cvssv3_attack_complexity=general_cvssv3_attack_complexity,
                               general_cvssv3_attack_vector=general_cvssv3_attack_vector,
                               general_cvssv3_availability_impact=general_cvssv3_availability_impact,
                               general_cvssv3_base_score=general_cvssv3_base_score,
                               general_cvssv3_base_severity=general_cvssv3_base_severity,
                               general_cvssv3_confidentiality_impact=general_cvssv3_confidentiality_impact,
                               general_cvssv3_integrity_impact=general_cvssv3_integrity_impact,
                               general_cvssv3_privileges_required=general_cvssv3_privileges_required,
                               general_cvssv3_scope=general_cvssv3_scope,
                               general_cvssv3_user_interaction=general_cvssv3_user_interaction,
                               general_cvssv3_version=general_cvssv3_version,
                               general_cvssv3_exploitability_score=general_cvssv3_exploitability_score,
                               general_cvssv3_impact_score=general_cvssv3_impact_score,
                               general_configurations_cve_data_version=general_configurations_cve_data_version,
                               general_configurations_nodes=general_configurations_nodes,
                               general_cwe=general_cwe,
                               general_products=general_products,
                               general_seen_wild=general_seen_wild,
                               general_references=general_references,
                               general_description=general_description,
                               general_date_modified=general_date_modified,
                               general_date_created=general_date_created,
                               general_exploits=general_exploits,
                               general_epss=general_epss)




@app.route("/search_indicators", methods=['GET', 'POST'])
def search_indicators():
    if request.method == 'GET':
        username = session['username']
        users = retrieve_users()
        user_dict = {user[1]: {'password': user[2], 'email': user[3], 'system': user[4], 'service': user[5], 'indicator': user[6]} for user in users}
        session['system'] = user_dict[username]['system']
        session['service'] = user_dict[username]['service']
        session['indicator'] = user_dict[username]['indicator']
        query = " ".join([session['system'], session['service'], session['indicator']])
        print("Getting of:", query)
        
        user_settings = query
    if request.method == 'POST':
        query = request.form.get('search_query', '')
        print(f"Received POST request with search query: {query}")
        user_settings = " ".join([session['system'], session['service'], session['indicator']])
        # You can fetch results from your database and cache them for future requests

    # Fetch indicators from cache or database based on query
    indicators_df = get_cleaned_indicator_data_from_database(query)
    indicators_list = []

    # Sort by the entire `general.date_modified` column in descending order
    indicators_df = indicators_df.sort_values(by='general.date_modified', ascending=False)
    indicators_df = indicators_df.drop_duplicates(subset='general.base_indicator.indicator', keep='first')
    unique_categories=[]
    if query==' ':
            # Check if DataFrame is not empty or null
        if indicators_df is not None and not indicators_df.empty:
        # Iterate through each row in the DataFrame
            for index, row in indicators_df.iterrows():
                # Extract specific values from the current row with default fallback values
                indicators_list.append({
                    'indicator': row.get('general.base_indicator.indicator', ''),
                    'base_indicator_type': row.get('general.base_indicator.type', ''),
                    'cvssv2_vulnerability': row.get('general.cvssv2.severity', 'N/A'),
                    'cvssv3_attack_complexity': row.get('general.cvssv3.cvssV3.attackComplexity', 'N/A'),
                    'cvssv3_base_severity': row.get('general.cvssv3.cvssV3.baseSeverity', 'N/A'),
                    'cvssv3_exploitability_score': float(row.get('general.cvssv3.exploitabilityScore', 0.0)),
                    'cvssv3_impact_score': float(row.get('general.cvssv3.impactScore', 0.0)),
                })
            return render_template('indicators_all_categories.html', indicators_list=indicators_list,unique_categories=unique_categories, user_settings=user_settings,user_logged_in=session['username'])



    else:
        # Check if DataFrame is not empty or null
        if indicators_df is not None and not indicators_df.empty:
        # Iterate through each row in the DataFrame
            for index, row in indicators_df.iterrows():
                # Extract specific values from the current row with default fallback values
                indicators_list.append({
                    'indicator': row.get('general.base_indicator.indicator', ''),
                    'base_indicator_type': row.get('general.base_indicator.type', ''),
                    'cvssv2_vulnerability': row.get('general.cvssv2.severity', 'N/A'),
                    'cvssv3_attack_complexity': row.get('general.cvssv3.cvssV3.attackComplexity', 'N/A'),
                    'cvssv3_base_severity': row.get('general.cvssv3.cvssV3.baseSeverity', 'N/A'),
                    'cvssv3_exploitability_score': float(row.get('general.cvssv3.exploitabilityScore', 0.0)),
                    'cvssv3_impact_score': float(row.get('general.cvssv3.impactScore', 0.0)),
                    'category': row.get('category', 'Uncategorized')  # Assuming 'category' is the correct field name
                })
        unique_categories = indicators_df['category'].unique()
    return render_template('indicators.html', indicators_list=indicators_list,unique_categories=unique_categories, user_settings=user_settings,user_logged_in=session['username'])




@app.route('/refresh_database',methods=['GET','POST'])
def refresh_database():
    if request.method == 'POST':
        
        return redirect(url_for('search_indicators'))



@app.route('/admin',methods=['GET','POST'])
def admin_page():
    if request.method=='GET':
        return redirect(url_for('manage_users'))




@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    if request.method == 'GET':
        users = retrieve_users() 
    
        return render_template('manage_users.html', users=users)  # Pass users to the template




@app.route('/edit_user', methods=['POST'])
def edit_user_endpoint():
    """Endpoint to edit user details."""
    # Get data from the form
    user_id = request.form.get('user_id')
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    system = request.form.get('system')
    service = request.form.get('service')
    indicator = request.form.get('indicator')

    # Check for empty fields and handle accordingly
    if not username or not password or not email or not system or not service or not indicator:
        return "All fields are required.", 400  # Return an error message if any fields are empty

    print(f"Editing user with ID: {user_id}")
    print(f"New details: {username}, {password}, {email}, {system}, {service}, {indicator}")

    # Call the edit_user function
    edit_user(user_id, username, password, email, system, service, indicator)

      # Return a success message
    users = retrieve_users()  # Fetch the updated list of users
    # Redirect or return a success message
    return redirect(url_for('manage_users'))




@app.route('/delete_user', methods=['POST'])
def delete_user_endpoint():
    """Endpoint to delete a user."""
    # Call the delete_user function
    user_id = request.form.get('user_id')
    print(f"Deleting user with ID: {user_id}")
    delete_user(user_id)
    users = retrieve_users()  # Fetch the updated list of users
    # Redirect or return a success message
    return redirect(url_for('manage_users'))




@app.route('/create_new_user', methods=['POST'])
def create_user_endpoint():
    """Endpoint to create a new user."""
    # Get data from the form
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    system = request.form.get('system')
    service = request.form.get('service')
    indicator = request.form.get('indicator')

    # Check for required fields
    if not username or not email or not password or not system or not service or not indicator:
        return redirect(url_for('manage_users'))  # Return an error if required fields are empty

    # Call the create_user function
    add_user(username, password, email, system, service, indicator)
    users = retrieve_users()  # Fetch the updated list of users

    return redirect(url_for('manage_users'))




@app.route('/search_domains', methods=["GET", "POST"])
def search_domains():
    query = ''  # Default value for query
    if request.method == "POST":
        query = request.form.get('search_query', '').strip()  # Retrieve and clean the search query
    
    # Fetch domains and tags based on the search query
    domains = search_domain_with_query(query)
    tags = extract_tags_by_indicator("domain")
    
    # Render the template with the search query included
    return render_template('search_domains.html', 
                           indicators_list=domains, 
                           tags=tags, 
                           search_query=query,user_logged_in=session['username'])




@app.route('/search_urls', methods=["GET", "POST"])
def search_urls():
    query = ''
    if request.method == "POST":
        query = request.form['search_query']  # Get the query from the POST request

    # Perform the search or any other operations based on the query
    urls = search_url_with_query(query)
    tags = extract_tags_by_indicator("URL")

    # Pass the query and other data to the template
    return render_template('search_urls.html', indicators_list=urls, tags=tags, search_query=query,user_logged_in=session['username'])




@app.route('/search_ip4', methods=["GET", "POST"])
def search_ip4():
    query = ''
    if request.method == "POST":
        query = request.form['search_query']  # Get the query from the POST request

    # Perform the search based on the query
    ipv4 = search_ip4_with_query(query)  # Make sure this function returns valid data
    tags = extract_tags_by_indicator("IPv4")  # Make sure this returns valid tags

    # Pass the query, ipv4 results, and tags to the template
    return render_template('search_ip4.html', indicators_list=ipv4, tags=tags, search_query=query,user_logged_in=session['username'])




@app.route('/search_hostnames', methods=["GET", "POST"])
def search_hostnames():
    query = ''
    if request.method == "POST":
        query = request.form['search_query']  # Get the query from the POST request

    # Perform the search or any other operations based on the query
    hostnames = search_hostnames_with_query(query)  # Make sure this function returns valid data
    tags = extract_tags_by_indicator("hostname")  # Make sure this function returns valid data

    # Pass the query, hostnames, and tags to the template
    return render_template('search_hostnames.html', indicators_list=hostnames, tags=tags, search_query=query,user_logged_in=session['username'])



@app.route('/domain_full_detail', methods=['GET', 'POST'])
def domain_full_detail():
    if request.method == 'POST':
        indicator = request.form['indicator']
        indicator_type = request.form['base_indicator_type']
        df = otx_object.get_indicator_details_full(get_indicator_type(indicator_type), indicator)
        df = json_normalize(df)

        def safe_get(column_name):
          
            if column_name in df.columns and df[column_name][0] != '':
                return df[column_name][0]
            else:
                return random.randint(1, 10)  

        # Extract general information
        general_sections = safe_get('general.sections')
        general_whois = safe_get('general.whois')
        general_alexa = safe_get('general.alexa')
        general_indicator = safe_get('general.indicator')
        general_type = safe_get('general.type')
        general_type_title = safe_get('general.type_title')
        general_base_indicator_id = int(safe_get('general.base_indicator.id')) if safe_get('general.base_indicator.id') else random.randint(1, 10)
        general_base_indicator_indicator = safe_get('general.base_indicator.indicator')
        general_base_indicator_access_type = safe_get('general.base_indicator.access_type')
        general_pulse_info_count = safe_get('general.pulse_info.count')
        general_pulse_info_pulses = safe_get('general.pulse_info.pulses')
        general_pulse_info_references = safe_get('general.pulse_info.references')
        general_pulse_info_related_alienvault_malware_families = safe_get('general.pulse_info.related.alienvault.malware_families')
        general_pulse_info_related_other_malware_families = safe_get('general.pulse_info.related.other.malware_families')

        # Extract malware information
        malware_data = safe_get('malware.data')
        malware_size = safe_get('malware.size')
        malware_count = safe_get('malware.count')

        # Extract URL list information
        try:
        # Attempt to normalize and extract the URL list
            url_list = json_normalize(df['url_list.url_list'][0])
            url_list = url_list.to_dict(orient='records')[0]
        except IndexError:
        # If an IndexError occurs, skip the processing and assign a default value
            print("Index out of range. Skipping this entry.")
            url_list = None  # Or use an empty dict or other default value as needed

        # Extract passive DNS information
        passive_dns_count = safe_get('passive_dns.count')
        passive_dns_data = safe_get('passive_dns.passive_dns')
        url_list = [url_list]
        print(url_list)
        print(passive_dns_data)
        # Pass all variables to the HTML template
        return render_template('domain_full_details.html', 
                               user_logged_in=session['username'],
            
            general_sections=general_sections,
            general_whois=general_whois,
            general_alexa=general_alexa,
            general_indicator=general_indicator,
            general_type=general_type,
            general_type_title=general_type_title,
            general_base_indicator_id=general_base_indicator_id,
            general_base_indicator_indicator=general_base_indicator_indicator,
            general_base_indicator_access_type=general_base_indicator_access_type,
            general_pulse_info_count=general_pulse_info_count,
            general_pulse_info_pulses=general_pulse_info_pulses,
            general_pulse_info_references=general_pulse_info_references,
            general_pulse_info_related_alienvault_malware_families=general_pulse_info_related_alienvault_malware_families,
            general_pulse_info_related_other_malware_families=general_pulse_info_related_other_malware_families,
            malware_data=malware_data,
            malware_size=malware_size,
            malware_count=malware_count,
            url_list=url_list,
            passive_dns_count=passive_dns_count,
            passive_dns_data=passive_dns_data
        )
    



@app.route('/ip4_full_detail', methods=['GET', 'POST'])
def ip4_full_detail():
    if request.method == 'POST':
        indicator = request.form['indicator']
        indicator_type = request.form['base_indicator_type']
      
        df = otx_object.get_indicator_details_full(get_indicator_type(indicator_type), indicator)
        df = json_normalize(df)

        def safe_get(column_name):
           
            if column_name in df.columns and df[column_name][0] != '':
                return df[column_name][0]
            else:
                return ' ' 

        # Extract general information
        general_whois = safe_get('general.whois')
        general_reputation = safe_get('general.reputation')
        general_indicator = safe_get('general.indicator')
        general_type = safe_get('general.type')
        general_type_title = safe_get('general.type_title')
        general_base_indicator_id = int(safe_get('general.base_indicator.id')) if safe_get('general.base_indicator.id') else random.randint(1, 10)
        general_base_indicator_indicator = safe_get('general.base_indicator.indicator')
        general_pulse_info_count = safe_get('general.pulse_info.count')
        general_pulse_info_pulses = safe_get('general.pulse_info.pulses')
        general_pulse_info_references = safe_get('general.pulse_info.references')
        general_asn = safe_get('general.asn')
        general_city_data = safe_get('general.city_data')
        general_city = safe_get('general.city')
        general_region = safe_get('general.region')
        general_continent_code = safe_get('general.continent_code')
        general_country_code3 = safe_get('general.country_code3')
        general_country_code2 = safe_get('general.country_code2')
        general_subdivision = safe_get('general.subdivision')
        general_latitude = safe_get('general.latitude')
        general_postal_code = safe_get('general.postal_code')
        general_longitude = safe_get('general.longitude')
        general_accuracy_radius = safe_get('general.accuracy_radius')
        general_country_code = safe_get('general.country_code')
        general_country_name = safe_get('general.country_name')
        general_dma_code = safe_get('general.dma_code')
        general_charset = safe_get('general.charset')
        general_area_code = safe_get('general.area_code')
        general_flag_title = safe_get('general.flag_title')
        general_sections = safe_get('general.sections')

        # Extract malware information
        malware_data = safe_get('malware.data')
        malware_size = safe_get('malware.size')
        
        # Extract passive DNS information
        passive_dns_count = safe_get('passive_dns.count')
        passive_dns_data = safe_get('passive_dns.passive_dns')
        

        # Pass all variables to the HTML template
        return render_template('ipv4_full_details.html', 
                               user_logged_in=session['username'],
            general_whois=general_whois,
            general_reputation=general_reputation,
            general_indicator=general_indicator,
            general_type=general_type,
            general_type_title=general_type_title,
            general_base_indicator_id=general_base_indicator_id,
            general_base_indicator_indicator=general_base_indicator_indicator,
            general_pulse_info_count=general_pulse_info_count,
            general_pulse_info_pulses=general_pulse_info_pulses,
            general_pulse_info_references=general_pulse_info_references,
            general_asn=general_asn,
            general_city_data=general_city_data,
            general_city=general_city,
            general_region=general_region,
            general_continent_code=general_continent_code,
            general_country_code3=general_country_code3,
            general_country_code2=general_country_code2,
            general_subdivision=general_subdivision,
            general_latitude=general_latitude,
            general_postal_code=general_postal_code,
            general_longitude=general_longitude,
            general_accuracy_radius=general_accuracy_radius,
            general_country_code=general_country_code,
            general_country_name=general_country_name,
            general_dma_code=general_dma_code,
            general_charset=general_charset,
            general_area_code=general_area_code,
            general_flag_title=general_flag_title,
            general_sections=general_sections,
            malware_data=malware_data,
            malware_size=malware_size,
            passive_dns_count=passive_dns_count,
            passive_dns_data=passive_dns_data
        )




@app.route('/url_full_detail', methods=['GET', 'POST'])
def url_full_detail():
    if request.method == 'POST':
        indicator = request.form['indicator']
        indicator_type = request.form['base_indicator_type']
        df = otx_object.get_indicator_details_full(URL, indicator)
        df = json_normalize(df)
        def safe_get(column_name):
            return df[column_name][0] if column_name in df.columns else ''

        general_sections = safe_get('general.sections')
        general_indicator = safe_get('general.indicator')
        general_type_title = safe_get('general.type_title')
        general_base_indicator_id = int(safe_get('general.base_indicator.id')) if safe_get('general.base_indicator.id') else 0
        general_pulse_info_count = safe_get('general.pulse_info.count')
        general_pulse_info_pulses = safe_get('general.pulse_info.pulses')
        general_pulse_info_references = safe_get('general.pulse_info.references')
        general_pulse_info_related_alienvault_malware_families = safe_get('general.pulse_info.related.alienvault.malware_families')
        general_pulse_info_related_alienvault_industries = safe_get('general.pulse_info.related.alienvault.industries')
        general_pulse_info_related_other_adversary = safe_get('general.pulse_info.related.other.adversary')
        general_pulse_info_related_other_malware_families = safe_get('general.pulse_info.related.other.malware_families')
        general_pulse_info_related_other_industries = safe_get('general.pulse_info.related.other.industries')
        general_false_positive = safe_get('general.false_positive')
        general_whois = safe_get('general.whois')

        # Convert the first entry of the nested list to a dictionary
        url_list = []
        try:
            url_list = json_normalize(df['url_list.url_list'][0][0])
            url_list = url_list.to_dict(orient='records')[0]
            url_list = [url_list]
        except:
            pass
        # Extract specific URL list information
       
        url_list_city_data = get_geo_data()  

        url_list_net_loc = safe_get('url_list.net_loc') or 'example.com'
        url_list_city = safe_get('url_list.city') or url_list_city_data['city']
        url_list_region = safe_get('url_list.region') or url_list_city_data['region']
        url_list_continent_code = safe_get('url_list.continent_code') or url_list_city_data['continent_code']
        url_list_country_code3 = safe_get('url_list.country_code3') or url_list_city_data['country_code3']
        url_list_country_code2 = safe_get('url_list.country_code2') or url_list_city_data['country_code2']
        url_list_subdivision = safe_get('url_list.subdivision') or url_list_city_data['subdivision']
        url_list_latitude = safe_get('url_list.latitude') or url_list_city_data['latitude']
        url_list_postal_code = safe_get('url_list.postal_code') or url_list_city_data['postal_code']
        url_list_longitude = safe_get('url_list.longitude') or url_list_city_data['longitude']
        url_list_accuracy_radius = safe_get('url_list.accuracy_radius') or url_list_city_data['accuracy_radius']
        url_list_country_code = safe_get('url_list.country_code') or url_list_city_data['country_code']
        url_list_country_name = safe_get('url_list.country_name') or url_list_city_data['country_name']
        url_list_dma_code = safe_get('url_list.dma_code') or url_list_city_data['dma_code']
        url_list_charset = safe_get('url_list.charset') or url_list_city_data['charset']
        url_list_area_code = safe_get('url_list.area_code') or url_list_city_data['area_code']
        url_list_flag_title = safe_get('url_list.flag_title') or url_list_city_data['flag_title']
        # Pass all variables to the HTML template
        return render_template('url_full_detail.html', 
                               user_logged_in=session['username'],
            general_sections=general_sections,
            general_indicator=general_indicator,
            general_type_title=general_type_title,
            general_base_indicator_id=general_base_indicator_id,
            general_pulse_info_count=general_pulse_info_count,
            general_pulse_info_pulses=general_pulse_info_pulses,
            general_pulse_info_references=general_pulse_info_references,
            general_pulse_info_related_alienvault_malware_families=general_pulse_info_related_alienvault_malware_families,
            general_pulse_info_related_alienvault_industries=general_pulse_info_related_alienvault_industries,
            general_pulse_info_related_other_adversary=general_pulse_info_related_other_adversary,
            general_pulse_info_related_other_malware_families=general_pulse_info_related_other_malware_families,
            general_pulse_info_related_other_industries=general_pulse_info_related_other_industries,
            general_false_positive=general_false_positive,
            general_whois=general_whois,
            url_list_net_loc=url_list_net_loc,
            url_list_city_data=url_list_city_data,
            url_list_city=url_list_city,
            url_list_region=url_list_region,
            url_list_continent_code=url_list_continent_code,
            url_list_country_code3=url_list_country_code3,
            url_list_country_code2=url_list_country_code2,
            url_list_subdivision=url_list_subdivision,
            url_list_latitude=url_list_latitude,
            url_list_postal_code=url_list_postal_code,
            url_list_longitude=url_list_longitude,
            url_list_accuracy_radius=url_list_accuracy_radius,
            url_list_country_code=url_list_country_code,
            url_list_country_name=url_list_country_name,
            url_list_dma_code=url_list_dma_code,
            url_list_charset=url_list_charset,
            url_list_area_code=url_list_area_code,
            url_list_flag_title=url_list_flag_title
        )




def refresh_automatically(days):
    print("Refreshing Database")
    refresh(days)
    print(f"Data for {days} added to database.")




def run_flask_app():
    app.run(port=5500)




@app.route("/login_admin",methods=['GET','POST'])
def login_admin():
    if request.method=='POST':
        username=request.form['username']
        password=request.form['password']
        if username=='siteadmin' and password=='siteadmin':
            session['username']=username
            return redirect(url_for('admin_page'))
        else:
            return redirect(url_for('admin_page'))
    return render_template('login.html')




if __name__ == '__main__':
 
    
    processes = []
    days = [i for i in range(1,10)]
    print(days)

    for each in days:
        process = Process(target=refresh_automatically, args=(each,))
        process.start()
        processes.append(process)

    flask_process = Process(target=run_flask_app)
    flask_process.start()

    try:
        time.sleep(10000) 
        stop_event.set() 
    finally:
        for process in processes:
            process.join() 

        print("Background processes have been stopped, but Flask continues to run.")