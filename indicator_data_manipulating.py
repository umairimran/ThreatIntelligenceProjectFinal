def convert_cvss_data(cvss_data: Dict[str, Any]) -> Dict[str, Any]:
    # Create a denormalized representation of the CVSS data
    denormalized_cvss = {
        'access_complexity': cvss_data.get('Access-Complexity'),
        'access_vector': cvss_data.get('Access-Vector'),
        'authentication': cvss_data.get('Authentication'),
        'availability_impact': cvss_data.get('Availability-Impact'),
        'score': float(cvss_data.get('Score', 0)),  # Convert score to float
        'confidentiality_impact': cvss_data.get('Confidentiality-Impact'),
        'integrity_impact': cvss_data.get('Integrity-Impact'),
        'vector_string': cvss_data.get('vectorString')
    }
    return denormalized_cvss


def convert_pulse_info_in_indicator(pulses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Initialize a list to store denormalized pulse data
    pulses_data = []

    for data in pulses:  # Iterate directly over the list of pulse data
        # Handle missing fields with defaults or None
        tags = ', '.join(data.get('tags', []))
        targeted_countries = ', '.join(data.get('targeted_countries', [])) or None
        malware_families = ', '.join(mf.get('display_name', '') for mf in data.get('malware_families', []))
        attack_ids = ', '.join(f"{aid.get('id', '')} - {aid.get('display_name', '')}" for aid in data.get('attack_ids', []))
        industries = ', '.join(data.get('industries', []))
        groups = ', '.join(data.get('groups', [])) or None
        
        # Create denormalized data dictionary
        denormalized_data = {
            'id': data.get('id'),
            'name': data.get('name'),
            'description': data.get('description'),
            'modified': datetime.fromisoformat(data['modified']),
            'created': datetime.fromisoformat(data['created']),
            'tags': tags,
            'public': bool(data.get('public', False)),
            'adversary': data.get('adversary') or None,
            'targeted_countries': targeted_countries,
            'malware_families': malware_families,
            'attack_ids': attack_ids,
            'industries': industries,
            'TLP': data.get('TLP'),
            'export_count': data.get('export_count', 0),
            'upvotes_count': data.get('upvotes_count', 0),
            'downvotes_count': data.get('downvotes_count', 0),
            'votes_count': data.get('votes_count', 0),
            'locked': data.get('locked', False),
            'pulse_source': data.get('pulse_source'),
            'validator_count': data.get('validator_count', 0),
            'comment_count': data.get('comment_count', 0),
            'follower_count': data.get('follower_count', 0),
            'vote': data.get('vote', 0),
            'author_username': data['author'].get('username'),
            'author_id': data['author'].get('id'),
            'avatar_url': data['author'].get('avatar_url'),
            'is_subscribed': data['author'].get('is_subscribed', False),
            'is_following': data['author'].get('is_following', False),
            'indicator_counts': json.dumps(data.get('indicator_type_counts', {})),
            'indicator_count': data.get('indicator_count', 0),
            'is_author': data.get('is_author', False),
            'is_subscribing': data.get('is_subscribing', None),
            'subscriber_count': data.get('subscriber_count', 0),
            'modified_text': data['modified_text'].strip() if data.get('modified_text') else '',
            'is_modified': data.get('is_modified', False),
            'groups': groups,
            'in_group': data.get('in_group', False),
            'threat_hunter_scannable': data.get('threat_hunter_scannable', False),
            'threat_hunter_has_agents': data.get('threat_hunter_has_agents', 0),
            'related_indicator_type': data.get('related_indicator_type'),
            'related_indicator_is_active': bool(data.get('related_indicator_is_active', False))
        }
        
        # Append the denormalized data to the list
        pulses_data.append(denormalized_data)

    return pulses_data

def convert_cvss_v2_data(cvss_v2_data: Dict[str, Any]) -> Dict[str, Any]:
    # Create a denormalized representation of the CVSS v2 data
    denormalized_cvss_v2 = {
        'access_complexity': cvss_v2_data.get('accessComplexity'),
        'access_vector': cvss_v2_data.get('accessVector'),
        'authentication': cvss_v2_data.get('authentication'),
        'availability_impact': cvss_v2_data.get('availabilityImpact'),
        'base_score': float(cvss_v2_data.get('baseScore', 0)),  # Ensure base score is a float
        'confidentiality_impact': cvss_v2_data.get('confidentialityImpact'),
        'integrity_impact': cvss_v2_data.get('integrityImpact'),
        'vector_string': cvss_v2_data.get('vectorString'),
        'version': cvss_v2_data.get('version')
    }
    return denormalized_cvss_v2


def convert_cvssv3_data(cvss_data):
    # Create a denormalized structure for CVSS v3
    denormalized_cvss_data = {
        'attack_complexity': cvss_data.get('attackComplexity'),
        'attack_vector': cvss_data.get('attackVector'),
        'availability_impact': cvss_data.get('availabilityImpact'),
        'base_score': cvss_data.get('baseScore'),
        'base_severity': cvss_data.get('baseSeverity'),
        'confidentiality_impact': cvss_data.get('confidentialityImpact'),
        'integrity_impact': cvss_data.get('integrityImpact'),
        'privileges_required': cvss_data.get('privilegesRequired'),
        'scope': cvss_data.get('scope'),
        'user_interaction': cvss_data.get('userInteraction'),
        'vector_string': cvss_data.get('vectorString'),
        'version': cvss_data.get('version'),
    }
    return denormalized_cvss_data

def convert_configurations_data(config_data):
    # Initialize a list to hold the flattened data
    flattened_data = []

    # Extract CVE data version
    cve_data_version = config_data.get('CVE_data_version')

    # Extract nodes and their children (if any)
    for node in config_data.get('nodes', []):
        for cpe in node.get('cpe_match', []):
            flattened_data.append({
                'cve_data_version': cve_data_version,
                'cpe23_uri': cpe.get('cpe23Uri'),
                'vulnerable': cpe.get('vulnerable')
            })
    
    return flattened_data