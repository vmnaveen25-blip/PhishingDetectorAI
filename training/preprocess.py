import pandas as pd

df = pd.read_csv(r"D:/PhishingDetecterAI/dataset/phishing.csv")

print(df.head())
print(df.info())
print(df.isnull().sum())
print(df.duplicated().sum())
df.columns = df.columns.str.strip()
X = df.drop(["Result"], axis=1)
y = df["Result"]

print("\nFeatures (X):")
print(X.head())

print("\nLabels (y):")
print(y.head())