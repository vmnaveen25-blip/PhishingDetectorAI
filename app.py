import joblib
import pandas as pd
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from feature_extractor import extract_features

# ==================================================
# Paths
# ==================================================

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = BASE_DIR / "models" / "phishing_model.pkl"
FEATURE_PATH = BASE_DIR / "models" / "feature_names.pkl"

# ==================================================
# Load Model
# ==================================================

model = joblib.load(MODEL_PATH)
feature_names = joblib.load(FEATURE_PATH)

print("✅ Model Loaded Successfully")

# ==================================================
# FastAPI
# ==================================================

app = FastAPI(title="Phishing Detector AI")

app.add_middleware(
    CORSMiddleware,

    # Development only
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://192.168.56.1:5173",
        "http://192.168.1.3:5173",
    ],

    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================================================
# Request Model
# ==================================================

class URLRequest(BaseModel):
    url: str

# ==================================================
# Home
# ==================================================

@app.get("/")
def home():
    return {
        "message": "Phishing Detector AI Running Successfully"
    }

# ==================================================
# Prediction
# ==================================================

@app.post("/predict")
def predict(request: URLRequest):

    try:

        features = extract_features(request.url)

        df = pd.DataFrame([features])

        df = df[feature_names]

        probability = model.predict_proba(df)[0]

        # probability[0] -> Legitimate
        # probability[1] -> Phishing

        legitimate_confidence = probability[0] * 100
        phishing_confidence = probability[1] * 100

        # Default prediction
        prediction = model.predict(df)[0]

        # Your custom decision rule
        if legitimate_confidence >= 80:
            result = "Legitimate Website"
            prediction = -1
            confidence = legitimate_confidence
        else:
            result = "Phishing Website"
            prediction = 1
            confidence = phishing_confidence

        return {

            "url": request.url,

            "prediction": int(prediction),

            "result": result,

            "confidence": round(confidence,2),

            "features": features

        }

    except Exception as e:

        return {

            "success": False,

            "error": str(e)

        }