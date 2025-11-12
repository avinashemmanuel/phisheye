# 🛡️ PhishEye – AI-Powered Anti-Phishing Detector

PhishEye is a web-based and API-driven phishing detection system that uses **Machine Learning (Random Forest)** to classify URLs as **Safe**, **Suspicious**, or **Phishing**.  
Built using **FastAPI**, **JavaScript**, and **TailwindCSS**, it aims to make browsing safer for everyone.

---<br>

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)


## 🚀 Features
- Real-time phishing URL detection
- Machine Learning–based classification
- Web interface + REST API
- Database logging for learning and analytics

---

## 🧠 Tech Stack
- **Frontend:** HTML, TailwindCSS, JavaScript
- **Backend:** Python (FastAPI)
- **ML Libraries:** scikit-learn, pandas, numpy
- **Database:** SQLite / PostgreSQL
- **Hosting:** Render / Heroku (optional)

---

## ⚙️ Setup Instructions

### 1️⃣ Clone the Repository
bash<br>
git clone https://github.com/avinashemmanuel/phisheye.git<br>
cd phisheye<br>

### 2️⃣ Create a Virtual Environment
bash<br>
python -m venv venv<br>
source venv/bin/activate  # Windows: venv\Scripts\activate<br>

### 3️⃣ Install Dependencies
bash<br>
pip install -r requirements.txt<br>

### 4️⃣ Run the App
bash<br>
uvicorn main:app --reload<br>

Open http://localhost:8000 to use the app.<br>

| Method | Endpoint   | Description                     |
| ------ | ---------- | ------------------------------- |
| POST   | `/scan`    | Analyze a URL                   |
| GET    | `/history` | Retrieve scan history           |
| POST   | `/report`  | Report incorrect classification |
<br>

### 📊 Example Response
JSON:<br>
{<br>
  "url": "http://example-login-update.com",<br>
  "classification": "Phishing",<br>
  "confidence": 0.95<br>
}<br>


### 🤝 Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you’d like to modify.


### 📜 License
This project is licensed under the MIT License – see the LICENSE file for details.


### 👨‍💻 Author
Avinash Ben Emmanuel<br>
Department of Computer Science, Doon University<br>
📧 24ce24@doonuniversity.ac.in<br>
