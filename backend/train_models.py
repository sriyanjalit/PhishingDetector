import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from models import PhishingDetector
from feature_extraction import FeatureExtractor

def load_training_data():
    """
    Load and prepare training data from CSV files.
    You should have two CSV files:
    - legitimate_urls.csv: Contains legitimate URLs
    - phishing_urls.csv: Contains known phishing URLs
    """
    try:
        # Load legitimate URLs
        legitimate_df = pd.read_csv('data/legitimate_urls.csv')
        legitimate_df['is_phishing'] = 0
        
        # Load phishing URLs
        phishing_df = pd.read_csv('data/phishing_urls.csv')
        phishing_df['is_phishing'] = 1
        
        # Combine datasets
        df = pd.concat([legitimate_df, phishing_df], ignore_index=True)
        return df
    except Exception as e:
        print(f"Error loading training data: {e}")
        return None

def extract_features(urls):
    """Extract features from a list of URLs"""
    feature_extractor = FeatureExtractor()
    features_list = []
    
    for url in urls:
        features = feature_extractor.extract_all_features(url)
        features_list.append(features)
    
    return pd.DataFrame(features_list)

def main():
    # Create necessary directories
    os.makedirs('models', exist_ok=True)
    os.makedirs('data', exist_ok=True)
    
    # Load training data
    print("Loading training data...")
    df = load_training_data()
    if df is None:
        print("Please ensure you have the training data files in the data/ directory")
        return
    
    # Extract features
    print("Extracting features...")
    X = extract_features(df['url'])
    y = df['is_phishing']
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Save scaler parameters
    np.save('models/scaler_mean.npy', scaler.mean_)
    np.save('models/scaler_scale.npy', scaler.scale_)

    # Initialize and train model
    print("Training models...")
    detector = PhishingDetector()
    detector.train(X_train_scaled, y_train)
    
    # Evaluate on test set
    print("Evaluating models...")
    test_predictions = [detector.predict(x)['is_phishing'] for x in X_test_scaled]
    print("Classification Report:")
    print(classification_report(y_test, test_predictions))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, test_predictions))
    
    # Save models
    print("Saving models...")
    detector.save_models()
    print("Training completed successfully!")

if __name__ == "__main__":
    main()