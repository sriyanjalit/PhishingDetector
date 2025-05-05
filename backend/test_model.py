import pandas as pd
from models import PhishingDetector
from feature_extraction import FeatureExtractor
import numpy as np

def test_url(url, detector, feature_extractor):
    """Test a single URL and print the results"""
    features = feature_extractor.extract_all_features(url)
    result = detector.predict(np.array(list(features.values())).reshape(1, -1))
    
    print(f"\nURL: {url}")
    print(f"Is Phishing: {result['is_phishing']}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Random Forest Vote: {result['model_votes']['random_forest']}")
    print(f"Decision Tree Vote: {result['model_votes']['decision_tree']}")
    print("-" * 80)

def main():
    # Load the trained model
    detector = PhishingDetector()
    feature_extractor = FeatureExtractor()
    
    # Test legitimate URLs
    print("\n=== Testing Legitimate URLs ===")
    legitimate_urls = [
        "https://www.google.com",
        "https://www.microsoft.com/en-us/microsoft-365",
        "https://www.apple.com/mac",
        "https://www.amazon.com/dp/B07ZPKN6YR",
        "https://www.paypal.com/us/home",
        "https://www.netflix.com/browse",
        "https://www.linkedin.com/jobs",
        "https://www.github.com/explore",
        "https://www.wikipedia.org/wiki/Main_Page",
        "https://www.youtube.com/feed/subscriptions"
    ]
    
    for url in legitimate_urls:
        test_url(url, detector, feature_extractor)
    
    # Test phishing URLs
    print("\n=== Testing Phishing URLs ===")
    phishing_urls = [
        "https://google-verify-account.xyz",
        "https://facebook-secure-verify.tk",
        "https://microsoft-account-verify.ga",
        "https://apple-id-verify.cf",
        "https://amazon-account-verify.top",
        "https://paypal-verify-account.club",
        "https://netflix-account-verify.work",
        "https://linkedin-verify-identity.tk",
        "https://twitter-account-verify.xyz",
        "https://instagram-verify-account.ga"
    ]
    
    for url in phishing_urls:
        test_url(url, detector, feature_extractor)
    
    # Test some edge cases
    print("\n=== Testing Edge Cases ===")
    edge_cases = [
        "https://google.com.verify-account.xyz",
        "https://facebook.com-secure-verify.tk",
        "https://microsoft.com-account-verify.ga",
        "https://apple.com-id-verify.cf",
        "https://amazon.com-account-verify.top"
    ]
    
    for url in edge_cases:
        test_url(url, detector, feature_extractor)

if __name__ == "__main__":
    main() 