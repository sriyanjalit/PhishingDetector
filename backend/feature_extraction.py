import re
from urllib.parse import urlparse

class FeatureExtractor:
    def __init__(self):
        # Known suspicious TLDs
        self.suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'xyz', 'top', 'club', 'work', 'site', 'online', 'info'}
        
        # Known suspicious keywords
        self.suspicious_keywords = {
            'verify-account', 'secure-verify', 'account-verify', 'verify-now',
            'account-suspended', 'account-locked', 'verify-identity',
            'unusual-activity', 'suspicious-activity', 'verify-payment',
            'payment-verify', 'verify-card', 'card-verify', 'verify-bank',
            'bank-verify', 'verify-wallet', 'wallet-verify', 'login', 'signin',
            'secure', 'account', 'password', 'credential', 'update', 'confirm',
            'authenticate', 'recover', 'unlock', 'access', 'restricted'
        }
        
        # Common brand names that might be impersonated
        self.brand_names = {
            'google', 'facebook', 'apple', 'microsoft', 'amazon', 'paypal',
            'netflix', 'linkedin', 'twitter', 'instagram', 'whatsapp', 'telegram',
            'github', 'wikipedia', 'youtube', 'reddit', 'spotify', 'dropbox',
            'slack', 'zoom', 'adobe'
        }
        
        # Common legitimate domain endings
        self.legitimate_domains = {
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int'
        }
    
    def extract_all_features(self, url):
        """Extract all features from URL"""
        try:
            parsed_url = urlparse(url)
            path = parsed_url.path
            query = parsed_url.query
            domain = parsed_url.netloc.lower()
            
            # Basic features
            features = {
                'url_length': min(len(url) / 100.0, 1.0),  # Normalize length
                'num_dots': min(url.count('.') / 5.0, 1.0),  # Normalize count
                'num_hyphens': min(url.count('-') / 5.0, 1.0),
                'num_underscores': min(url.count('_') / 5.0, 1.0),
                'num_slashes': min(url.count('/') / 5.0, 1.0),
                'num_digits': min(sum(c.isdigit() for c in url) / 10.0, 1.0),
                'num_special_chars': min(len(re.findall(r'[^a-zA-Z0-9]', url)) / 20.0, 1.0),
                'domain_length': min(len(domain) / 50.0, 1.0),
                'path_length': min(len(path) / 50.0, 1.0),
                'has_https': 1 if url.startswith('https://') else 0
            }
            
            # Domain analysis
            domain_parts = domain.split('.')
            tld = domain_parts[-1] if domain_parts else ''
            
            features.update({
                'has_suspicious_tld': 1 if tld in self.suspicious_tlds else 0,
                'has_legitimate_tld': 1 if tld in self.legitimate_domains else 0,
                'num_subdomains': min((len(domain_parts) - 1) / 3.0, 1.0),
                'has_ip_address': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
                'has_port_number': 1 if ':' in domain else 0,
                'has_suspicious_keywords': 1 if any(keyword in url.lower() for keyword in self.suspicious_keywords) else 0,
                'has_brand_name': 1 if any(brand in domain for brand in self.brand_names) else 0
            })
            
            # URL structure analysis
            features.update({
                'has_suspicious_encoding': 1 if '%' in url or any(c in url for c in ['\\x', '\\u']) else 0,
                'has_data_uri': 1 if url.startswith('data:') else 0,
                'has_javascript_uri': 1 if url.startswith('javascript:') else 0,
                'has_empty_hostname': 1 if not domain or domain.startswith('.') else 0,
                'has_random_strings': 1 if any(len(part) >= 6 and re.match(r'^[a-zA-Z0-9]+$', part) and 
                                             not any(brand in part.lower() for brand in self.brand_names)
                                             for part in re.split(r'[/._-]', url)) else 0,
                'has_complex_query': 1 if len(query) > 20 or query.count('=') > 2 else 0,
                'has_encoded_strings': 1 if re.search(r'[a-fA-F0-9]{16,}|[A-Za-z0-9+/]{20,}=*', url) else 0
            })
            
            # Brand impersonation analysis
            features.update({
                'has_brand_with_suspicious_tld': 1 if any(brand in domain for brand in self.brand_names) and tld in self.suspicious_tlds else 0,
                'has_brand_in_path': 1 if any(brand in path.lower() for brand in self.brand_names) else 0,
                'has_brand_in_query': 1 if any(brand in query.lower() for brand in self.brand_names) else 0,
                'has_suspicious_path': 1 if any(keyword in path.lower() for keyword in self.suspicious_keywords) else 0,
                'has_suspicious_query': 1 if any(keyword in query.lower() for keyword in self.suspicious_keywords) else 0
            })
            
            # Additional phishing indicators
            features.update({
                'has_brand_with_hyphen': 1 if any(f"{brand}-" in domain or f"-{brand}" in domain for brand in self.brand_names) else 0,
                'has_brand_with_digit': 1 if any(f"{brand}{digit}" in domain or f"{digit}{brand}" in domain for brand in self.brand_names for digit in '0123456789') else 0,
                'has_brand_with_suspicious_tld': 1 if any(f"{brand}.{tld}" in domain for brand in self.brand_names for tld in self.suspicious_tlds) else 0,
                'has_suspicious_brand_combination': 1 if any(f"{brand1}-{brand2}" in domain or f"{brand2}-{brand1}" in domain for brand1 in self.brand_names for brand2 in self.brand_names if brand1 != brand2) else 0
            })
            
            return features
            
        except Exception as e:
            print(f"Error extracting features: {str(e)}")
            return {} 