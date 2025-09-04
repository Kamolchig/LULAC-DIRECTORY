# LULAC Membership Portal

This repository contains a Flask-based membership portal designed for the League of United Latin American Citizens (LULAC). The application provides a secure, password-protected website where members can register, log in, manage their contact information, and browse a directory of other members.

## Features

* **Account Creation:** Prospective members can register with an email, password, and optional fields such as name, council number, city, state, phone, occupation, and additional notes.
* **Authentication:** Registered users can log in and log out. Passwords are securely hashed for protection.
* **Profile Management:** Logged-in members can view and update their personal information at any time.
* **Member Directory:** Once authenticated, members can browse a directory of all registered users, with filtering options for city, state, occupation, and council number.
* **Session Management:** User sessions are managed securely using Flask's session handling.

## Running the Application

1. Ensure you have Python 3 installed.
2. Create a virtual environment and activate it:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application:
   ```bash
   python app.py
   ```
5. Open your web browser and navigate to `http://localhost:5000` to access the membership portal.

## File Structure

```
lulac-membership-portal/
├── app.py                # Main application code for the Flask web application
├── requirements.txt      # Dependencies required for the project
├── membership.db         # SQLite database for storing user information and sessions
├── static/
│   └── style.css         # CSS styles for the application
├── templates/
│   ├── base.html         # Base template for the application
│   ├── home.html         # Template for the home page
│   ├── login.html        # Template for the login page
│   ├── register.html     # Template for the registration page
│   ├── profile.html      # Template for the user profile page
│   └── directory.html     # Template for the member directory page
└── README.md             # Documentation for the project
```

## Customization Notes

* **Security:** Ensure to implement secure password hashing and consider using HTTPS for production.
* **Styling:** The CSS file can be customized to match LULAC branding or to integrate frameworks like Bootstrap.
* **Database Management:** The SQLite database file `membership.db` will be created automatically on the first run. To reset the database, delete this file and restart the application.

## Limitations

* This application is intended for demonstration purposes and may lack advanced security features. Use caution if deploying in a public environment.
* For larger organizations or complex requirements, consider a full-featured membership management system.