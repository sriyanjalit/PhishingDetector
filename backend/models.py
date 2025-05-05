from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
import numpy as np
import joblib
import os

class PhishingDetector:
    def __init__(self):
        # Initialize models with better parameters
        self.rf_model = RandomForestClassifier(
            n_estimators=2000,  # Increased number of trees
            max_depth=30,      # Increased depth
            min_samples_split=10,
            min_samples_leaf=4,
            class_weight={0: 1, 1: 2},  # Give more weight to phishing class
            random_state=42
        )
        self.dt_model = DecisionTreeClassifier(
            max_depth=25,
            min_samples_split=10,
            min_samples_leaf=4,
            class_weight={0: 1, 1: 2},  # Give more weight to phishing class
            random_state=42
        )
        self.models_trained = False
        
        # Try to load models during initialization
        try:
            models_path = os.path.join(os.path.dirname(__file__), 'models')
            if os.path.exists(models_path):
                self.load_models(models_path + '/')
        except Exception as e:
            print(f"Warning: Could not load models during initialization: {e}")
    
    def train(self, X, y):
        """Train both models with cross-validation"""
        self.rf_model.fit(X, y)
        self.dt_model.fit(X, y)
        self.models_trained = True
    
    def predict(self, features):
        """Make prediction using weighted voting from all models"""
        if not self.models_trained:
            raise Exception("Models need to be trained first!")
            
        if not hasattr(self, 'rf_model') or not hasattr(self, 'dt_model'):
            raise Exception("Models not properly initialized!")
        
        # Convert features to numpy array if needed
        if not isinstance(features, np.ndarray):
            features = np.array(features).reshape(1, -1)
        
        try:
            # Get predictions and probabilities from each model
            rf_pred = self.rf_model.predict(features)[0]
            dt_pred = self.dt_model.predict(features)[0]
            
            rf_prob = self.rf_model.predict_proba(features)[0][1]  # Probability of phishing
            dt_prob = self.dt_model.predict_proba(features)[0][1]  # Probability of phishing
            
            # Calculate weighted confidence score (Random Forest has higher weight)
            confidence = (0.95 * rf_prob + 0.05 * dt_prob)  # Increased weight on Random Forest
            
            # More sensitive threshold for phishing detection
            # Mark as phishing if either model thinks it's phishing with decent confidence
            is_phishing = (rf_pred and rf_prob > 0.6) or (dt_pred and dt_prob > 0.7)
            
            return {
                'is_phishing': bool(is_phishing),
                'confidence': float(confidence),
                'model_votes': {
                    'random_forest': bool(rf_pred),
                    'decision_tree': bool(dt_pred)
                }
            }
        except Exception as e:
            print(f"Error during prediction: {e}")
            # Return a safe default prediction
            return {
                'is_phishing': False,
                'confidence': 0.0,
                'model_votes': {
                    'random_forest': False,
                    'decision_tree': False
                },
                'error': str(e)
            }
    
    def save_models(self, path_prefix='./models/'):
        """Save all models to files"""
        os.makedirs(os.path.dirname(path_prefix), exist_ok=True)
        joblib.dump(self.rf_model, f'{path_prefix}rf_model.joblib')
        joblib.dump(self.dt_model, f'{path_prefix}dt_model.joblib')
    
    def load_models(self, path_prefix='./models/'):
        """Load all models from files"""
        if not os.path.exists(f'{path_prefix}rf_model.joblib') or not os.path.exists(f'{path_prefix}dt_model.joblib'):
            raise Exception("Model files not found!")
            
        try:
            self.rf_model = joblib.load(f'{path_prefix}rf_model.joblib')
            self.dt_model = joblib.load(f'{path_prefix}dt_model.joblib')
            self.models_trained = True
            print("Models loaded successfully!")
        except Exception as e:
            print(f"Error loading models: {e}")
            raise 