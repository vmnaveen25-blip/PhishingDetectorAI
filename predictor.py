import joblib
import pandas as pd
from feature_extractor import extract_features

# --------------------------------------
# Load Model
# --------------------------------------
model = joblib.load("phishing_model.pkl")
print("✅ Model Loaded Successfully!")

# --------------------------------------
# Input URL
# --------------------------------------
url = input("\nEnter URL: ").strip()

try:
    # --------------------------------------
    # Extract Features
    # --------------------------------------
    features = extract_features(url)

    # --------------------------------------
    # Convert to DataFrame
    # (Must match training dataset order)
    # --------------------------------------
    feature_df = pd.DataFrame([features])

    feature_df = feature_df[[
        "having_IP_Address",
        "URLURL_Length",
        "Shortining_Service",
        "having_At_Symbol",
        "double_slash_redirecting",
        "Prefix_Suffix",
        "having_Sub_Domain",
        "SSLfinal_State",
        "Domain_registeration_length",
        "Favicon",
        "port",
        "HTTPS_token",
        "Request_URL",
        "URL_of_Anchor",
        "Links_in_tags",
        "SFH",
        "Submitting_to_email",
        "Abnormal_URL",
        "Redirect",
        "on_mouseover",
        "RightClick",
        "popUpWidnow",
        "Iframe",
        "age_of_domain",
        "DNSRecord",
        "web_traffic",
        "Page_Rank",
        "Google_Index",
        "Links_pointing_to_page",
        "Statistical_report"
    ]]

    # --------------------------------------
    # Predict
    # --------------------------------------
    # -------------------------------
    # Count Suspicious Features
    # -------------------------------

    suspicious_count = sum(1 for value in features.values() if value == 1)

    print(f"\nSuspicious Features : {suspicious_count}/30")

    # -------------------------------
    # Model Prediction
    # -------------------------------

    prediction = model.predict(feature_df)[0]

    confidence = model.predict_proba(feature_df)[0]
    confidence_score = max(confidence) * 100

    # -------------------------------
    # Final Decision
    # -------------------------------

    if prediction == 1 and suspicious_count < 8:
        print("Prediction : 🚨 PHISHING WEBSITE")

    else:
        print("Prediction : ✅ LEGITIMATE WEBSITE")

        print(f"Confidence : {confidence_score:.2f}%")

        print("\nExtracted Features:")
        for key, value in features.items():
            print(f"{key:30} : {value}")

except Exception as e:
    print("\n❌ Error:", e)