from flask import Flask, request, jsonify
from flask_cors import CORS
from models import PhishingDetector
from feature_extraction import FeatureExtractor
import numpy as np
from sklearn.preprocessing import StandardScaler

app = Flask(__name__)
CORS(app)

# Initialize the detector
detector = PhishingDetector()
feature_extractor = FeatureExtractor()
print("Models loaded successfully!")

# Initialize scaler (ensure it matches the one used during training)
scaler = StandardScaler()
scaler.mean_ = np.load('models/scaler_mean.npy')
scaler.scale_ = np.load('models/scaler_scale.npy')

# Modify analyze_url to apply scaling
def analyze_url(url):
    try:
        # Extract features
        features = feature_extractor.extract_all_features(url)
        print(f"Analyzing URL: {url}")
        
        # Convert features to numpy array
        feature_array = np.array(list(features.values())).reshape(1, -1)
        
        # Apply scaling
        feature_array = scaler.transform(feature_array)
        
        # Get prediction
        result = detector.predict(feature_array)
        
        # Add risk factors based on features
        risk_factors = []
        
        if features.get('has_suspicious_tld'):
            risk_factors.append("Suspicious top-level domain detected")
        
        if features.get('has_suspicious_keywords'):
            risk_factors.append("Suspicious keywords found in URL")
            
        if features.get('has_brand_with_suspicious_tld'):
            risk_factors.append("Brand name used with suspicious domain")
            
        if features.get('has_brand_with_hyphen'):
            risk_factors.append("Brand name used with hyphen (common in phishing)")
            
        if features.get('has_brand_with_digit'):
            risk_factors.append("Brand name used with numbers (common in phishing)")
            
        if features.get('has_suspicious_brand_combination'):
            risk_factors.append("Multiple brand names combined (suspicious pattern)")
            
        if features.get('has_random_strings'):
            risk_factors.append("Random-looking strings detected in URL")
            
        if features.get('has_complex_query'):
            risk_factors.append("Suspicious query parameters detected")
            
        if features.get('has_encoded_strings'):
            risk_factors.append("Suspicious encoded strings detected")
            
        if features.get('has_ip_address'):
            risk_factors.append("IP address used instead of domain name")
            
        if features.get('has_suspicious_encoding'):
            risk_factors.append("Suspicious URL encoding detected")
            
        if features.get('has_empty_hostname'):
            risk_factors.append("Empty or invalid hostname detected")
            
        if features.get('has_port_number'):
            risk_factors.append("Non-standard port number detected")
            
        if features.get('has_data_uri'):
            risk_factors.append("Data URI scheme detected (potential risk)")
            
        if features.get('has_javascript_uri'):
            risk_factors.append("JavaScript URI scheme detected (potential risk)")
        
        result['risk_factors'] = risk_factors
        print(f"Analysis result: {result}")
        return result
        
    except Exception as e:
        print(f"Error analyzing URL: {str(e)}")
        raise

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'No URL provided'}), 400
            
        url = data['url']
        print(f"Received analysis request for URL: {url}")
        
        result = analyze_url(url)
        return jsonify(result)
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting Flask server...")
    app.run(host='0.0.0.0', port=5000, debug=True)