# Web Security Project
By. WAUMANS Alec (58399) and PUCHALSKI Dorian (60093)
## Description of the project
The primary objective of this project is to design a secure web application that allows registered user to log in and upload files (or repositories) into a server.  
Through this project, we demonstrate advanced security features while providing functionalities for user management, file storage, and directory sharing.   
The project aims to implement best practices in security to mitigate risks and vulnerabilities often associated with web applications.  
Some not implemented features, due to some inconvienences, will be explained by providing the explanation of the vulnerability, how to mitigate the risk and the implementation idea.  

## Project Structure
```
SeciProject/  
├── app.py                      # Main application file  
├── requirements.txt            # Python dependencies  
├── .env                        # Secret variables  (to create by user due to secrets)
├── .env.example                # Secret variables template
├── instance/  
│   └── database.db             # SQLite DB (dev)
├── private/                    # Private artifacts (e.g., cert keys, 2FA QR images)
├── uploads/                    # Uploaded files directory  
├── static/  
│   └── css/                    # CSS files for styling  
├── templates/
│   ├── 2fa.html                # 2FA verification page 
│   ├── 429.html                # Too many login attempts page  
│   ├── dashboard.html          # Dashboard  
│   ├── home.html               # Home page  
│   ├── login.html              # Login page  
│   ├── logs.html               # Logs page  
│   ├── register.html           # Register page  
│   ├── shared_by_me.html       # Shared folders by me page  
│   ├── shared_with_me.html     # Shared folders with me page  
│   ├── users.html              # List of users registered page  
│   ├── view_directory.html     # View files in a directory  
│   └── view_shared_folder.html # View files in a shared directory.
```
## Project Execution (x64 Ubuntu 22.04 & 64x Windows 10)
Before building the project, make sure to create the `.env` file by copying the content of `.env.example` and changing the variables to what will be communicated to you by the developpers. 
### Ubuntu
1. Make sure to have Python 3.12 installed :
```
$ python3 --version
```
If not, install it :
```
$ sudo apt update
$ sudo apt install python3.12
```
2. Make sure pip is installed :
```
$ sudo apt install -y python3-pip
```
3. Run the startup script :
```
$ chmod +x start.sh     # If it's not executable somehow.
$ ./start.sh
```
### Windows
1. Make sure to have Python 3.12 installed. You can install it from the official Python site or do it in PowerShell :
```
> winget install Python.Python.3.12
> py -3.12 --version
```
2. Run the script manually by double-clicking start script in project directory.
3. Or run the script in Git Bash :
```
$ ./start.sh
```
### After startup
If you execute the project for the first time, you will by asked to create an admin account. This is for development and exam purpose only to show some features that a normal user doesn't have.
1. Create a username and password (confirm it).
2. Scan the QR code with Google Authenticator app. Close the QR code window.
3. Open your browser and go to `https://localhost:5000`.
4. Accept the risk, it's normal, our certificates are hand-made.
5. Log in with your admin account or register a new one.

## Key Features
#### Authentication & Sessions
- `BCrypt` for user password hashing.
- `Argon2id` KDF for per-file encryption keys (salted; Fernet-compatible).
- `2FA (TOTP)` with Google Authenticator. Admin has a recovery TOTP seed stored server-side for account recovery if the user loses their QR.
- `reCAPTCHA` on login/registration (server-side verification with timeout + fail-closed).
- **Rate limiting :** 3 failed login attempts → lockout for 1 minute.
- **Session timeouts :** absolute session lifetime of 20 min. + inactivity timeout of 5 min.
- **Secure cookies :** `HTTPOnly`, `Secure`, `SameSite`.
- **Back-button lockout :** protected routes require an active session; "go back" won't reveal previous user's data after logout.

#### Authorization & Sharing
- **Directory sharing** with explicit permissions(`download`, `add`, `delete` combinations).
- **Access control** enforced on every route (has to be owner or shared folder + permission check).
- **Username blacklist** : users cannot register with reserved names like `"Admin"`.

#### File, Directory & Metadata Handling:
- Upload, delete and download files (extensions allowed : `.jpeg`, `.jpg`, `.png`, `.pdf` and `.gif`).
- Create, delete, and share directories with your contacts.
- **Max upload size** : 16MB
- **Confidentiality** : files are stored as encrypted blobs (`*.enc`) using keys derived via `Argon2id` and encrypted with `Fernet`.
- **Zero-Knowledge encryption** : files are encrypted client-side through `WebCrypto AES-GCM-256`
- **Path traversal protection** : strict storage-name validation + safe joins + realpath boundary checks.
- **Secure delete** : overwrite-then-unlink routine within uploads root.
- **DB storage model :** original directory names and filenames are stored in the DB for UI display (accepted risk). On disk, names are randomized (`uuid.hex.enc`) to avoid leaking semantics through the filesystem.

#### Frontend & Transport Security
- `CSRF`: `Flask-WTF`tokens on all state-changing forms.
- `CSP` & `HTTPS`: `Flask-Talisman` enforces `HTTPS`, `HSTS`, `CSP`, `X-Frame-Options`, `Referrer-Policy`, `X-Content-Type-Options`, etc.
- **No mixed content** : cache disabled on auth pages.

#### Logging & Monitoring
- **Redacted structured logs** : filenames, directory names, and usernames are redacted or replaced with IDs.
- **UTC, timezone-aware timestamps** (ISO8601 with `+00:00`).
- **Admin-only log access** (read only).
- **Logging of IP** for traceability.

#### Administration
- **Admin account creation** only via CLI on the machine hosting the code.
- **Filesystem permissions** : `uploads/` and `private/` readable only by service account/admin. Because it's not served by a web server. This is changed manually and not applicable when project pulled from git repository.

## Main File Structure - app.py
1. Flask application configuration.
2. Database models for users, contacts, shared folder, and contact requests.
3. Forms for user registration, login, and file uploads.
4. Routes for managing authentification, file operations, and contacts.
5. Running the flask application.

> Developers note : we acknowledge that best practice would be the split the whole file into multiple files, each fulfilling the role of each section of app.py.

## Project Dependencies
### `argon2-cffi`
- **Description :**
Python bindings for the Argon2 password hashing and key derivation algorithm.
- **Security Contribution :**
It's memory-hard and CPU-intensive, slowing brute-force attacks and making GPU/ASIC cracking much harder.
- **Why Used :**
It's generally considered more secure than the previously used PBKDF2-HMAC-SHA256 thanks to its resistance to GPU attacks. Used to derive per-file encryption keys from user-provided passwords securely.

### `asgiref`
- **Description :**
Provides a standard interface for writing asynchronous servers and managing asynchronous operations in web frameworks like Flask when dealing with real-time communications or background tasks.
- **Security Contribution :**
Ensures proper handling of asynchronous operations to prevent resource locking or race conditions.
Helps in creating responsive, scalable applications that can handle concurrent requests securely.
- **Why Used :**
The project includes asynchronous tasks and managing a Flask web server (e.g., `Flask-Limiter`). `asgiref` ensures compatibility with ASGI (Asynchronous Server Gateway Interface) standards, enabling efficient task management.

### `bcrypt`
- **Description :** 
Implements the Bcrypt hashing algorithm, which is widely used for securely hashing passwords.
- **Security Contribution :**
Protects user passwords by using a computationally expensive algorithm, making brute-force attacks and dictionary attacks impractical.
Includes a built-in salt, ensuring that even identical passwords have unique hashes.
Resistant to precomputed hash attacks (rainbow tables).
- **Why Used :**
To securely hash user account passwords before storing them in the database, ensuring they cannot be reversed in the event of a data breach.

### `cffi` - C Foreign Function Interface
- **Description :** 
A library for calling C code from Python. It is a dependency of bcrypt, as Bcrypt is implemented in C for performance reasons.
- **Security Contribution :**
Allows Python to use secure, well-optimized C libraries like Bcrypt.
- **Why Used :** 
Required by Bcrypt and `argon2-cffi` to provide secure password hashing functionality.

### `click`
- **Description :** 
A library for creating command-line interfaces (CLI) in Python applications.
- **Security Contribution :**
Ensures user input in CLI commands is sanitized and validated to prevent injection attacks.

### `cryptography`
- **Description :** 
Python cryptography toolkit providing high-level recipes and low-level primitives.
- **Security Contribution :**
Allows Python to use secure, well-optimized C libraries like Bcrypt.
- **Why Used :** 
For file encryption/decryption using `Fernet` (AES + HMAC) with keys derived from `Argon2id`. Also, verified by the Python Cryptographic Authority.

### `email-validator`
- **Description :**
Validates email addresses to ensure they are well-formed and potentially deliverable.
- **Security Contribution :**
Prevents invalid or malicious email inputs that could be used to exploit the application.
Helps avoid garbage data in the database, which could interfere with application logic or be used in injection attacks.
- **Why Used :**
To validate user email inputs during registration, ensuring only valid email addresses are accepted.

### `Flask`
- **Description :**
The core web framework used to build the application. Flask provides routing, request handling, and templating capabilities.
- **Security Contribution :**
Supports secure session management and CSRF protection when paired with Flask-WTF.
Includes protection against common web vulnerabilities, such as injection attacks.
- **Why Used :**
It is the main framework for developing the web application, offering simplicity and extensibility.

### `Flask-Bcrypt`
- **Description :**
Integrates Bcrypt hashing into Flask applications for password hashing and verification.
- **Security Contribution :**
Simplifies password hashing and verification, ensuring best practices are followed.
Automatically salts passwords and uses a strong, slow hashing algorithm.
- **Why Used :** 
To securely hash and verify passwords in a Flask application.

### `Flask-Limited`
- **Description :**
Extension providing rate limiting.
- **Security Contribution :**
Prevents brute-force and abuse by limiting requests per IP or user.
- **Why Used :**
To limit login attempts and protect critical routes.

### `Flask-Login`
- **Description :**
Provides user session management for Flask applications, including login, logout, and session tracking.
- **Security Contribution :**
Manages secure user sessions, preventing session hijacking.
Ensures user authentication status is checked before granting access to protected routes.
Supports session timeout and remember-me functionality to balance security and usability.
- **Why Used :**
To implement user authentication and manage user sessions securely.

### `Flask-SQLAlchemy`
- **Description :**
Adds SQLAlchemy ORM capabilities to Flask for interacting with the database in an object-oriented manner.
- **Security Contribution :**
Protects against SQL injection by using parameterized queries.
Simplifies database interactions, reducing the chance of writing insecure raw SQL queries.
- **Why Used :**
To manage database interactions securely and efficiently.
 
### `Flask-Talisman`
- **Description :**
It's a Flask extension to set HTTP security headers.
- **Security Contribution :**
Protects against SQL injection by using parameterized queries.
Simplifies database interactions, reducing the chance of writing insecure raw SQL queries. Enforces HTTPS, sets Content Security Policy (CSP), and other headers to reduce XSS, MITM and clickjacking risks.
- **Why Used :**
To add a secure-by-default HTTP header policy to all responses.

### `Flask-WTF`
- **Description :**
Provides integration of Flask with WTForms for handling and validating web forms.
- **Security Contribution :**
Adds CSRF protection to all forms, mitigating Cross-Site Request Forgery attacks.
Ensures user inputs are validated and sanitized before being processed, reducing the risk of injection attacks.
- **Why Used :**
To create and validate forms securely, with built-in CSRF protection.

### `greenlet`
- **Description :**
A lightweight coroutine library used by SQLAlchemy to manage concurrent database operations efficiently.
- **Security Contribution :**
Ensures database operations are thread-safe and non-blocking, preventing race conditions or deadlocks.
- **Why Used :**
Required by SQLAlchemy for managing database connections.

### `importlib-metadata`
- **Description :**
Provides access to metadata about installed Python packages. It is primarily a dependency for other packages.
- **Security Contribution :**
Ensures the application can reliably check for package versions, avoiding outdated or vulnerable dependencies.
- **Why Used :**
Required internally by Python and Flask to handle package metadata.

### `itsdangerous`
- **Description :**
Provides cryptographic signing capabilities for securely serializing data, such as session cookies or tokens.
- **Security Contribution :**
Ensures data integrity by preventing tampering with signed data.
Used in Flask for securely signing session data.
- **Why Used :**
To securely manage session cookies and protect sensitive data exchanged between the client and server.

### `Jinja2`
- **Description :**
The templating engine used by Flask to render dynamic HTML pages.
- **Security Contribution :**
Escapes user-provided data in templates by default, preventing Cross-Site Scripting (XSS) attacks.
Supports secure template inheritance, reducing the risk of template injection vulnerabilities.
- **Why Used :** 
To render HTML templates securely while protecting against XSS.

### `MarkupSafe`
- **Description :** 
Provides a way to safely handle and escape untrusted input in HTML and XML.
- **Security Contribution :**
Ensures that user-provided input is properly escaped to prevent XSS attacks.
- **Why Used :**
Used internally by Jinja2 to securely handle user input in templates.

### `pycparser`
- **Description :**
A C parser used by the cffi library to parse C code.

### `pyotp`
- **Description :**
Python library for generating and verifying one-time passwords (TOTP)
- **Security Contribution :**
Enables 2FA, reducing account takeover risks.
- **Why Used :**
For Google Authenticator 2FA integration.

### `python-dotenv`
- **Description :**
Loads environment variables from `.env` files.
- **Security Contribution :**
Keeps secrets out of the code by storing them securely in environment configs.
- **Why used :**
To manage sensitive settings like SECRET_KEY, DB URL, etc.

### `qrcode[pil]`
- **Description :**
Generates QR codes in Python with Pillow for image output
- **Security Contribution :**
Allows secure sharing of TOTP provisioning URIs without exposing the secret in plaintext.
- **Why Used :**
To generate scannable QR codes for user 2FA setup when they register.

### `requests`
- **Description :**
HTTP library for Python
- **Security Contribution :**
Supports secure TLS requests and certificate verification.
- **Why Used :**
To verify reCAPTCHA with Google securely.

### `six`
- **Description :**
Provides compatibility between Python 2 and 3.
- **Security Contribution :**
Ensures that security-critical libraries work consistently across Python versions.
- **Why Used :**
Used internally by dependencies to maintain compatibility.

### `SQLAlchemy`
- **Description :**
An ORM (Object-Relational Mapping) library for managing database interactions.
- **Security Contribution :**
Protects against SQL injection by enforcing parameterized queries.
Simplifies database operations, reducing the likelihood of insecure code.
- **Why Used :**
To handle database interactions securely and efficiently.

### `Werkzeug`
- **Description :**
A WSGI utility library used by Flask to handle HTTP requests, routing, and other low-level web server functionalities.
- **Security Contribution :**
Includes secure handling of HTTP requests and headers.
Provides tools for input validation and request parsing.
- **Why Used :**
Essential for Flask’s internal workings, including secure handling of web requests.

### `WTForms`
- **Description :**
A Python library for building and validating web forms.
- **Security Contribution :**
Validates and sanitizes user input to prevent injection attacks.
Ensures proper input formatting and constraints to avoid malformed data.
- **Why Used :**
To handle user input validation securely and simplify form creation.

## Security Checklist
1. **Do I properly ensure confidentiality?**  
- **Are sensitive data transmitted and stored properly?**  
*Sensitive data is considered here : user account passwords, file encryption passwords, TOTP codes, QR codes, filenames, directory names and file data.
All sensitive communications (login, registration, file uploads, directory managements, etc.) are transmitted over HTTPS, enforced by Flask-Talisman with a strong Content Security Policy.
Passwords are hashed using Argon2id with unique salts and strong parameters before storage.
Uploaded files are stored encrypted under a hashed/UUID filename in the filesystem to prevent interference from filenames and hide this sensitive information. The directory names are hashed the same way.
Original filenames and directory names are stored in the DB in plaintext for UI display only, which is an accepted design decision for usability (risk acknowledged).*  

- **Are sensitive requests sent to the server transmitted securely?**  
*Thanks to `Flask-WTF` and `WTForms`, CSRF tokens ensure the integrity of sensitive requests.
The use of Flask-Talisman enforces HTTPS for all requests, ensuring secure transmission of sensitive data over the network.
reCAPTCHA v2 is enforced on login and registration to mitigate bot-based brute force attacks.
Rate-limiting via `Flask-Limiter` restricts login attempts to 3 per minute per IP, and the 2FA verification attempts to 5 every 3 minutes.*

- **Does a system administrator have the ability to access any sensitive data?**  
*An administrator can only be created via a CLI script if there is no existing administrator. The responsability is on the developper (often administrator).
Admin can view server logs where sensitive data is redacted. They can access the database (so he can see the filename and directory name in plaintext, but not the passwords).
They can also access the `private/` directory containing `.pem` certificates and the admin QR code for 2FA only when root password is provbided.
Same for the `uploads/` directory, although all the content is hashed and encrypted.*
> Solutions : Before web deployment, it would be wise to not store plaintext names of files and directories in the database.

2. **Did I harden my authentication scheme?**  
*A reCAPTCHA v2 from Google is used and verified server-side (with a request timeout and fail-closed). There is also a 2FA verification with TOTP(Google Authenticator) required after password auth.
There is a QR code generated, but not saved, to have the authentication code for the account. The user can decide to save the QR code (accepted risk). In case of losing the QR code, the Admin can recover tbe access with the TOTP stored in the database (risk accepted).
The password policy is reinforced by requiring a minimum length password (here min. 8 characters), 1 capital letter, 1 number and 1 special character `!@#$%^&*()\-_=+[]{},.?/`.
Login is rate-limited to 3 failed login attempts with a 1min. lockout per IP.
Zero-knowledge auth wasn't implemented due to time and organisation restrictions.*
> Solutions : A zero-knowledge auth method has been thought (with WebAuthn) to replace the vulnerable standard password login, to avoid password snuffing and sending it to the server that is considered unsafe.

3. **Do I properly ensure integrity of stored data?**  
* Files are stored as Fernet ciphertext. Fernet verifies a built-in HMAC on every decrypt for tamper detection; any bit-flip or tampering causes decryption to fail.
Keys are derived with unique salts and fixed KDF parameters, preventing key reuse mistakes.
Flask-SQLAlchemy ensures consistent data storage thanks to his parameterized queries (for DB).
Form validation prevents tampering with input data. Logs are redacted to not provoke sensitive data leak if there is unauthorized access to the logs.*
> Solutions : It would be wise to check the integrity of the plaintext too with SHA-256.

4. **Do I properly ensure the integrity of sequences of items?**  
- **Does somebody has the ability to add or delete an item in a sequence, or edit an item
in a sequence, without being detected?**  
*DB constraints and ownership/permission checks on files, shared directories and owned directories prevent unauthorized actions (read, write and download).
Structured logs capture who did what, when (UTC), for post-incident review. So, any addition or deletion through the app is visible. Although, a malicious admin or DB access could still reorder or remove entries without leaving evidence.*
> Solutions : We could make the logging tamper-evident by adding an append-only, hash chained audit log. Each entry would store a hash of previous entry + its own content. That way, any hidden actions would break the chain.

5. **Do I properly ensure non-repudiation?**  
*User actions are authenticated, ensuring accountability. There are also logs recording almost everything that happens on the server. But we could use tamper-evident logs though.*
> Solution : Make the logs tamper-evident.

6. **Do my security features rely on secrecy, beyond cryptographic keys and access codes?**  
*We mostly tried to follow the Kerckhoffs's principle so the security doesn't depend on keeping the code, algorithms and endpoints secret.
We keep secret : account password hashes, per-file encryption keys, app/session/reCAPTCHA secrets (in .env).
We don't keep secret : algorithms & parameters, salts, randomized storage names and source code. We decided to store the plaintext file and directory names for usability. This is an accepted risk.*
> Solutions : Avoid storing the plaintext file and directory names. Keep no secrets in the repo by providing an `.env.example` and keep the real one out of VCS.

7. **Am I vulnerable to injection?**  
- *SQL Injection: The application uses SQLAlchemy ORM, which mitigates SQL injection risks by parameterizing queries. No raw SQL concatenation is used and input validation is done in WTForms with length and type checks.*
- *JavaScript Injection (XSS): Jinja2 auto-escapes variables in templates with explicit escaping when needed. CSP via Flask-Talisman blocks inline JS and unauthorized script sources. Uploaded filenames, directory names and usernames are sanitized before display.*
- *URL Injection/Open Redirect: All redirects use Flask's `url_for()` and no dynamic redirect targets are accepted from request parameters.*
- *Other injections: File names are validated using secure_filename, reducing the risk of path traversal vulnerabilities or command injection. No XML or YAML parsing,  or direct command-line calls from untrusted input.*

8. **Am I vulnerable to data remanence attacks?**  
*Recovered blobs from encrypted files remain unreadable without the key. Upon deletion of files and/or directories, a secure delete routines (overwrite-then-unlink) method is used.*
> Solutions : We should avoid storing plaintext data and check if secrets won't land in swap or core dumps.

9. **Am I vulnerable to fraudulent request forgery?**  
*CSRF tokens mitigate Cross-Site Request Forgery (CSRF) attacks. CSRFProtect injects and validates CSRF tokens for all form-based POST request. Session cookies are restricted to `Lax` making cross-origin cookie use harder.
Routes performing sensitive actions (uploading, deletions and sharing) are wrapped in `@login_required` and permission checks. Even if CSRF bypassed form validation somehow, 2FA and CAPTCHA add friction for automated malicious actions.*
> Solutions : Keep an eye on `GET` requests that may be CSRF-vulnerable.

10. **Am I monitoring enough user activity to detect malicious intents or analyze an attack a posteriori?**  
- **Am I properly sanitizing user input?**  
*User input is validated via WTForms (length/type) and escaped by Jinja2; CSP reduces XSS impact. Filenames pass `secure_filename()` and storage names are validated by regex. We didn't implement explicitly username sanitization but we use a blacklist (e.g. Admin).*

- **Did I implement some form of anomaly detection?**  
*We use rate-limiting on login and 2FA, reCAPTCHA which's activity we can control, log entries.*

- **Do I use a whistleblower client?**  
*No.*
> Solutions : We could implement whistleblower client, checking download spikes from one user, geovelocity (same account logs from two distant IP in a short time). Add regex rules for user username sanitization.

11. **Am I using components with known vulnerabilities?**  
*Dependencies like Flask, SQLAlchemy, and Bcrypt are well-maintained. However, regular updates and security reviews are necessary to ensure no known vulnerabilities exist.*
> Solutions : Regularly update the dependencies and use tools (e.g. `safety` or Dependabot) to monitor dependencies' known vulnerabilities.

12. **Is my system updated?**  
*The system's update status depends on the server environment. Regularly updating dependencies (e.g., pip install --upgrade) and the operating system is crucial for security.*
> Solutions : Automatically check and manage the versions of the Language, browsers, systems and avoid access to the server if the system is outdated or not supported.

13. **Is my access control broken (cf. OWASP 10)?**  
*Access control seems adequate for basic user actions (e.g., only logged-in users can access certain routes). There are authenticated sessions only, least privilege roles (admin is created only through CLI), object-level checks by checking ownership or share membership + required permission on the server before performing action.
Share model is authoritative since permissions are evaluated on each request through the DB. There is a deny by default model if there is no explicit match to a request. Logs view require admin role + login.*

14. **Is my authentication broken (cf. OWASP 10)?**  
*We implemented : secure password storage, zero-knowledge through client-side file encryption, transport security via Flask-Talisman, CAPTCHA, TOTP-based 2FA, rate-limiting for login and 2FA, session security with secure cookies and session timeout, generic error messages on login, environment-based secrets.*
> Solutions : Add permanent account lockout, zero-knowledge proof authentification (WebAuthn).

15. **Are my general security features misconfigured (cf. OWASP 10)?**  
*The use of Flask-Talisman ensures secure defaults like HTTPS and CSP, mitigating several misconfiguration risks.*
> Solutions : Ensure that https is implemented with certificates from a verified CA and not auto-signed one (which we did here only for the purpose of the project development).
