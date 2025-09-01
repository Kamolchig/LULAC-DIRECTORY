# LULAC Membership Portal

This repository contains a simple, self‑contained membership portal implemented
using only Python standard library modules.  It is designed to meet the
requirements of the League of United Latin American Citizens (LULAC) for a
password‑protected website where members can register, sign in, maintain
contact information and browse a directory of other members.

## Features

* **Account creation:** Prospective members can register with an email,
  password and optional fields such as name, council number, city, state,
  phone, occupation and additional notes.
* **Authentication:** Registered users can log in and log out.  Passwords are
  stored as SHA‑256 hashes for basic security (note that more secure
  algorithms should be used for production deployments).
* **Profile management:** Logged‑in members can view and update their own
  contact information at any time.
* **Member directory:** Once authenticated, members can browse a table of
  all registered users.  The directory offers simple filters for city,
  state, occupation and council number to help find and connect with
  other members.
* **Session management:** Sessions are tracked via cookies and stored in an
  SQLite database.

## Running the server

1. Ensure you have Python 3 installed (no external packages are required).
2. From a terminal, navigate into this `membership_portal` directory.
3. Run the server with:

   ```bash
   python3 server.py
   ```

4. Open your web browser and go to `http://localhost:8000`.  You should see
   the home page where you can register a new account or log in.

By default the server listens on port 8000.  You can change the port by
editing the last line of `server.py` or by modifying the `run_server` call.

## File structure

```
membership_portal/
├── server.py        # Main application code (HTTP server and route handlers)
├── membership.db    # SQLite database (auto‑created on first run)
├── static/
│   └── style.css    # Cascading Style Sheet for basic styling
└── README.md        # This file
```

The database file `membership.db` will be created automatically on the first
run.  If you want to start with a clean slate, simply delete this file
and restart the server.

## Customization notes

* **Security:** This implementation is intended as a demonstration.  For a
  production deployment you should:
  * Use a robust framework such as Flask or Django, which provide
    battle‑tested request handling, form validation and session
    management.
  * Replace the simple SHA‑256 password hashing with a slow hash such as
    bcrypt or Argon2 and incorporate unique salts.
  * Serve the site over HTTPS.
* **Styling:** The CSS provided offers a clean, minimalist interface.  You
  can customize `static/style.css` to match LULAC branding or integrate
  Bootstrap/Tailwind if desired.
* **Additional fields:** If you need to store more information (for example,
  membership status or committee roles), add new columns to the `users`
  table in `server.py` and extend the registration/profile forms
  accordingly.
* **Administrative tools:** Currently any authenticated user can browse the
  full directory.  You may wish to restrict certain features (such as
  editing/deleting users) to administrative accounts.  Implementing roles
  would require adding a `role` column to the `users` table and checking
  it in your handlers.

## Limitations

* Because this application does not rely on third‑party frameworks, it lacks
  many conveniences such as CSRF protection, templating engines and input
  validation.  Use caution if deploying this in a public environment.
* The membership portal is intended for moderate traffic.  For larger
  organizations or complex requirements, consider a full‑featured CRM or
  membership management system.