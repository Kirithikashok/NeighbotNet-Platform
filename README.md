# NeighbotNet-Platform
The NeighborNet Platform is a web-based application developed to foster collaboration within local communities by connecting residents with verified individuals who possess various skills or tools. Users can register on the platform, verify their identity through official documents, add and manage their skill sets, and share or borrow tools.

## 🚀 Features

- 🔐 User Authentication (Register/Login/Logout)
- 👤 User Profiles with photo uploads
- 🛠️ Add and view tools shared by neighbors
- 🎓 Add skills with certificate uploads
- 🔍 Search for skills and tools
- 🛡️ **Admin Dashboard** to verify certificates

## 📁 Project Structure

NeighborNet/ │ ├── app.py # Main Flask application ├── database.db # SQLite3 database ├── templates/ # HTML templates │ ├── base.html │ ├── home.html │ ├── login.html │ ├── register.html │ ├── profile.html │ ├── add_skill.html │ ├── view_skills.html │ ├── add_tool.html │ ├── view_tools.html │ └── admin.html # Admin dashboard │ ├── static/ │ └── uploads/ # Uploaded images and certificates │ ├── README.md └── requirements.txt


## 🧪 Requirements

- Python 3.7+
- Flask
- Flask SQLAlchemy
- Werkzeug

Install dependencies:

```bash
pip install -r requirements.txt
🛠️ How to Run

Clone the repo:
git clone https://github.com/your-username/NeighborNet.git
cd NeighborNet
Run the app:
python app.py
Visit:
http://127.0.0.1:5000/
👑 Admin Access

To access the admin dashboard:

Register a new user
In the SQLite database, set is_admin = 1 for that user:
UPDATE user SET is_admin = 1 WHERE email = 'admin@example.com';
Log in as that user and visit /admin-dashboard
✅ Certificate Verification

Admins can view a list of user-submitted skills
Each entry shows the uploaded certificate and a "Verify" button
Once verified, status updates to ✅ Verified
📌 Future Enhancements

Add categories for tools and skills
Chat or messaging system
Location-based neighbor filtering
Mobile app version
🧡 Made with love for local communities.


---

Let me know if you’d like this customized with your GitHub repo link, screenshots, or a badge section!
