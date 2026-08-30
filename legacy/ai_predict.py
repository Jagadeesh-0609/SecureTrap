import pickle
import json

model = pickle.load(open("model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

with open("test_logs.json") as f:
    for line in f:
        data = json.loads(line)
        cmd = data["input"]
        X = vectorizer.transform([cmd])
        pred = model.predict(X)[0]
        print(cmd, "→", pred)
