import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
import pickle

data = pd.read_csv("dataset.csv")

vectorizer = CountVectorizer()
X = vectorizer.fit_transform(data["command"])

model = MultinomialNB()
model.fit(X, data["type"])

pickle.dump(model, open("model.pkl", "wb"))
pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))

print("Model trained successfully")
