 Flask Todo API with JWT and SendGrid

A simple Flask-based Todo API with JWT authentication and email notifications using SendGrid.

 Features
- User authentication with JWT
- Login and Register to Handle multiple users
- Create, update, delete todos
- Password reset  notifications via SendGrid
- Database migrations with Flask-Migrate

 Installation
1. Clone the repo:
   ```bash
   git clone https://github.com/your-username/your-repo-name.git
   cd your-repo-name
2. Setup
python -m venv venv
source venv/bin/activate   # on Mac/Linux
venv\Scripts\activate  

3.Set environment variables (create .env file):
SECRET_KEY=your-secret-key
DATABASE_URI=sqlite:///todos.db
SENDGRID_API_KEY=your-sendgrid-api-key

4.Running
flask run

Front end testing was done using Postman 
install required libraries on flask which includes , Flask,bluprints,migrate,flask_mysql and other
