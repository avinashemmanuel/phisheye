# 🛡️ PhishEye – AI-Powered Anti-Phishing Detector

PhishEye is a web-based and API-driven phishing detection system that uses **Machine Learning (Random Forest)** to classify URLs as **Safe**, **Suspicious**, or **Phishing**.  
Built using **FastAPI**, **JavaScript**, and **TailwindCSS**, it aims to make browsing safer for everyone.

---

## 🚀 Features
- Real-time phishing URL detection
- Machine Learning–based classification
- Web interface + REST API
- Database logging for learning and analytics
- Admin panel for managing whitelist and reports

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
bash
git clone https://github.com/avinashemmanuel/phisheye.git
cd phisheye

### 2️⃣ Create a Virtual Environment
bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

### 3️⃣ Install Dependencies
bash
pip install -r requirements.txt

### 4️⃣ Run the App
bash
uvicorn main:app --reload

Open http://localhost:8000 to use the app.

| Method | Endpoint   | Description                     |
| ------ | ---------- | ------------------------------- |
| POST   | `/scan`    | Analyze a URL                   |
| GET    | `/history` | Retrieve scan history           |
| POST   | `/report`  | Report incorrect classification |


### 📊 Example Response
JSON:
{
  "url": "http://example-login-update.com",
  "classification": "Phishing",
  "confidence": 0.95
}


### 🤝 Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you’d like to modify.


### 📜 License
This project is licensed under the MIT License – see the LICENSE file for details.


### 👨‍💻 Author
Avinash Ben Emmanuel
Department of Computer Science, Doon University
📧 24ce24@doonuniversity.ac.in
