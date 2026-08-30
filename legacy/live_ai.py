import subprocess
import json
import pickle

# Load model
model = pickle.load(open("model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

# Get docker container id
container_id = subprocess.getoutput("sudo docker ps -q")

# Get logs
logs = subprocess.getoutput(f"sudo docker logs {container_id}")

# Process logs
for line in logs.split("\n"):
    if '"input"' in line:
        try:
            data = json.loads(line)
            cmd = data["input"]

            X = vectorizer.transform([cmd])
            prediction = model.predict(X)[0]

            print(f"{cmd} → {prediction}")

        except:
            continue
