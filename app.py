import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import io
import sqlite3
import os
import csv
from functools import wraps
from werkzeug.utils import secure_filename
import pandas as pd
import shutil

app = Flask(__name__)
app.secret_key = 'supersecretkey'

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

DB = 'database.db'
VERIFICATION_CODE = "admin123"

# ---------- Login required ----------

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = session.get('username')
        session_token = session.get('session_token')

        if not username or not session_token:
            flash("❌ Please log in to continue.", "danger")
            return redirect(url_for('login'))

        conn = get_db()
        user = conn.execute("SELECT session_token FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if not user or user['session_token'] != session_token:
            session.clear()
            flash("⚠️ Your session has expired or you were logged out from another device.", "warning")
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function

"""
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("❌ Please log in to continue.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
"""
# ---------- Database Setup ----------
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if not os.path.exists(DB):
        conn = sqlite3.connect(DB)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license TEXT NOT NULL,
                company TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                status TEXT NOT NULL,
                session_token TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS call_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT, time TEXT, agent_name TEXT, ticket_no TEXT, ref_ticket_no TEXT,
                company_license TEXT, company_name TEXT, company_server TEXT, contact TEXT, language TEXT, query_type TEXT,
                query TEXT, status TEXT, duration TEXT, rating TEXT, desc TEXT, remarks TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS company_list (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_license TEXT UNIQUE,
                company_name TEXT,
                company_server TEXT
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS login_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                role TEXT,
                login_time TEXT,
                logout_time TEXT,
                ip_address TEXT
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS backup_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                backup_date TEXT NOT NULL,
                username TEXT NOT NULL
            )
        ''')

        conn.commit()
        conn.close()

# ---------- Routes ----------

@app.route('/get_company_details', methods=['POST'])
def get_company_details():
    license_number = request.json.get('license')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT company_name, company_server FROM company_list WHERE company_license = ?", (license_number,))
    result = cursor.fetchone()
    if result:
        return {'status': 'success', 'company_name': result[0], 'company_server': result[1]}
    else:
        return {'status': 'fail'}

# ---------- Routes ----------

@app.route('/')
@login_required
def home():
    if 'user' in session:
        return redirect(url_for('admin_dashboard' if session['role'] == 'admin' else 'agent_dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        license = request.form['license']
        company = request.form['company']
        username = request.form['username']
        password = request.form['password']
        code = request.form['verification']

        if code != VERIFICATION_CODE:
            flash("Invalid verification code", "danger")
        else:
            conn = get_db()
            exists = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if exists:
                flash("Username already exists", "warning")
            else:
                conn.execute('''
                    INSERT INTO users (license, company, username, password, role, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (license, company, username, generate_password_hash(password), 'admin', 'active'))
                conn.commit()
                flash("Registration successful! Please login.", "success")
                return redirect(url_for('login'))
            conn.close()
    return render_template('register.html')

# --- LOGIN ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        license = request.form['license']
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if not user or user['license'] != license:
            flash("Invalid license or username", "danger")
            return redirect(url_for('login'))

        if not check_password_hash(user['password'], password):
            flash("Incorrect password", "danger")
            return redirect(url_for('login'))

        if user['status'].lower() != 'active':
            flash("Account is inactive. Contact admin.", "danger")
            return redirect(url_for('login'))

        # ✅ Generate unique session token
        session_token = str(uuid.uuid4())
        session['session_token'] = session_token

        conn.execute("UPDATE users SET session_token = ? WHERE username = ?", (session_token, username))
        conn.commit()

        # ✅ Set session details
        session['license'] = user['license']
        session['username'] = user['username']
        session['role'] = user['role']
        session['status'] = user['status']
        session['login_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        session.permanent = True

        # ✅ Close previous open sessions in log
        conn.execute("""
            UPDATE login_log SET logout_time = ?
            WHERE username = ? AND logout_time IS NULL
        """, (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username))

        # ✅ Insert new login log
        ip_address = request.remote_addr
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO login_log (username, role, login_time, ip_address)
            VALUES (?, ?, ?, ?)
        """, (username, user['role'], session['login_time'], ip_address))
        conn.commit()

        session['log_id'] = cursor.lastrowid
        conn.close()

        return redirect(url_for('admin_dashboard' if user['role'] == 'admin' else 'agent_dashboard'))

    return render_template('login.html')


# --- LOGOUT (single session) ---
@app.route('/logout')
@login_required
def logout():
    log_id = session.get('log_id')
    if log_id:
        conn = get_db()
        logout_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute("UPDATE login_log SET logout_time = ? WHERE id = ?", (logout_time, log_id))
        conn.commit()
        conn.close()

    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# --- LOGOUT ALL SESSIONS (for this user) ---
@app.route('/logout_all')
@login_required
def logout_all():
    username = session.get('username')
    conn = get_db()

    # ✅ Clear session_token so all sessions become invalid
    conn.execute("UPDATE users SET session_token = NULL WHERE username = ?", (username,))
    conn.commit()

    # ✅ Mark all open login_log entries for this user
    logout_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn.execute("UPDATE login_log SET logout_time = ? WHERE username = ? AND logout_time IS NULL",
                 (logout_time, username))
    conn.commit()
    conn.close()

    session.clear()
    flash('You have been logged out from all devices.', 'info')
    return redirect(url_for('login'))
#-------------------------------------------------------    

@app.route('/view_login_logs')
@login_required
def view_login_logs():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM login_log ORDER BY login_time DESC")
    logs = c.fetchall()
    conn.close()
    return render_template('view_login_logs.html', license=session.get('license'), username=session.get('username'), logs=logs)


@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    # Total tickets created today
    c.execute("SELECT COUNT(*) FROM call_data WHERE DATE(date) = DATE('now')")
    total_tickets_today = c.fetchone()[0]

    # Tickets created today by this admin
    c.execute("SELECT COUNT(*) FROM company_list")
    total_company = c.fetchone()[0]

    # Total users active today
    c.execute("SELECT COUNT(DISTINCT username) FROM login_log WHERE DATE(login_time) = DATE('now')")
    total_active_users_today = c.fetchone()[0]

    # Currently logged in users (no logout_time)
    c.execute("SELECT COUNT(DISTINCT username) FROM login_log WHERE logout_time IS NULL")
    current_logged_in_users = c.fetchone()[0]

    # Total agents
    c.execute("SELECT COUNT(*) FROM users WHERE role = 'agent'")
    total_agents = c.fetchone()[0]

    # Total active agents
    c.execute("SELECT COUNT(*) FROM users WHERE role = 'agent' AND status = 'active'")
    total_active_agents = c.fetchone()[0]

    conn.close()

    return render_template(
        'admin_dashboard.html',
        license=session.get('license'),
        username=session.get('username'),
        login_time=session.get('login_time'),
        total_tickets=total_tickets_today,
        total_company=total_company,
        total_active_users=total_active_users_today,
        current_logins=current_logged_in_users,
        total_agents=total_agents,
        active_agents=total_active_agents
    )


@app.route('/agent_dashboard')
@login_required
def agent_dashboard():
    if session.get('role') != 'agent':
        return redirect(url_for('login'))
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    # Total tickets created today
    c.execute("SELECT COUNT(*) FROM call_data WHERE DATE(date) = DATE('now')")
    total_tickets_today = c.fetchone()[0]

    # Tickets created today by this admin
    c.execute("SELECT COUNT(*) FROM call_data WHERE DATE(date) = DATE('now') AND agent_name = ?", (session['username'],))
    your_tickets_today = c.fetchone()[0]

    # Total users active today
    c.execute("SELECT COUNT(DISTINCT username) FROM login_log WHERE DATE(login_time) = DATE('now')")
    total_active_users_today = c.fetchone()[0]

    # Currently logged in users (no logout_time)
    c.execute("SELECT COUNT(DISTINCT username) FROM login_log WHERE logout_time IS NULL")
    current_logged_in_users = c.fetchone()[0]

    # Total agents
    c.execute("SELECT COUNT(*) FROM users WHERE role = 'agent'")
    total_agents = c.fetchone()[0]

    # Total active agents
    c.execute("SELECT COUNT(*) FROM users WHERE role = 'agent' AND status = 'active'")
    total_active_agents = c.fetchone()[0]

    conn.close()
    return render_template(
        'agent_dashboard.html',
        license=session.get('license'),
        username=session.get('username'),
        login_time=session.get('login_time'),
        total_tickets=total_tickets_today,
        your_tickets=your_tickets_today,
        total_active_users=total_active_users_today,
        current_logins=current_logged_in_users,
        total_agents=total_agents,
        active_agents=total_active_agents
    )

# ------------- Tickets agent ----------------------
@app.route('/new_ticket', methods=['GET', 'POST'])
@login_required
def new_ticket():
    now = datetime.now()
    if request.method == 'POST':
        try:
            data = {
                'date': request.form.get('date'),
                'time': request.form.get('time'),
                'agent_name': session.get('username'),
                'ticket_no': request.form.get('ticket_no'),
                'ref_ticket_no': request.form.get('ref_ticket_no'),
                'company_license': request.form.get('license'),
                'company_name': request.form.get('company_name'),
                'company_server': request.form.get('company_server'),
                'contact': request.form.get('contact'),
                'language': request.form.get('language'),
                'query_type': request.form.get('query_type'),
                'query': request.form.get('query'),
                'status': request.form.get('status'),
                'duration': request.form.get('duration'),
                'rating': request.form.get('rating'),
                'desc': request.form.get('desc'),
                'remarks': request.form.get('remarks')
            }

            conn = get_db()
            conn.execute('''
                INSERT INTO call_data
                (date, time, agent_name, ticket_no, ref_ticket_no, company_license, company_name, company_server, contact, language, query_type, query, status, duration, rating, desc, remarks)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', tuple(data.values()))
            conn.commit()
            conn.close()

            flash("✅ Ticket submitted successfully!", "success")
            return redirect(url_for('new_ticket'))

        except Exception as e:
            flash(f"❌ Error: {str(e)}", "danger")

    return render_template('new_ticket.html',
                           current_date=now.strftime('%Y-%m-%d'),
                           current_time=now.strftime('%H:%M:%S'),
                           license=session.get('license'),
                           username=session.get('username'))

@app.route('/view_ticket')
@login_required
def view_ticket():
    conn = get_db()
    rows = conn.execute("SELECT * FROM call_data ORDER BY date DESC, time DESC").fetchall()
    return render_template('view_ticket.html',
                           license=session.get('license'),
                           username=session.get('username'),
                           call_data=rows)


@app.route('/edit_ticket_agent/<int:id>', methods=['POST'])
@login_required
def edit_ticket_agent(id):
    status = request.form.get('status')

    conn = get_db()
    conn.execute("UPDATE call_data SET status = ? WHERE id = ?", (status, id))
    conn.commit()
    flash("Ticket updated successfully!", "success")
    return redirect(url_for('view_ticket'))


@app.route('/download')
@login_required
def download_data():
    conn = get_db()
    rows = conn.execute("SELECT * FROM call_data").fetchall()

    # Step 1: Write CSV data to StringIO (text)
    output = io.StringIO()
    writer = csv.writer(output)

    if rows:
        writer.writerow(rows[0].keys())  # headers
        for row in rows:
            writer.writerow(row)

    # Step 2: Convert text to BytesIO (binary)
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8'))
    mem.seek(0)
    output.close()

    # Step 3: Send as downloadable file
    return send_file(mem,
                     mimetype='text/csv',
                     as_attachment=True,
                     download_name='call_data.csv')

# ------------- Tickets admin ----------------------
# tickets_admin-Main Page
@app.route('/tickets_admin')
@login_required
def tickets_admin():
    conn = get_db()
    rows = conn.execute("SELECT * FROM call_data ORDER BY date DESC, time DESC").fetchall()
    return render_template('tickets_admin.html',
                           license=session.get('license'),
                           username=session.get('username'),
                           call_data=rows)

# tickets_admin-Download CSV File
@app.route('/download_ticket_list')
@login_required
def download_ticket_list():
    conn = get_db()
    rows = conn.execute("SELECT * FROM call_data").fetchall()

    # Step 1: Write CSV data to StringIO (text)
    output = io.StringIO()
    writer = csv.writer(output)

    if rows:
        writer.writerow(rows[0].keys())  # headers
        for row in rows:
            writer.writerow(row)

    # Step 2: Convert text to BytesIO (binary)
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8'))
    mem.seek(0)
    output.close()

    # Step 3: Send as downloadable file
    return send_file(mem,
                     mimetype='text/csv',
                     as_attachment=True,
                     download_name='call_data.csv')


# tickets_admin-Edit Tickets
@app.route('/edit_ticket/<int:id>', methods=['POST'])
@login_required
def edit_ticket(id):
    data = request.form
    conn = get_db()
    conn.execute("""
        UPDATE call_data SET
            date=?, time=?, agent_name=?, ticket_no=?, ref_ticket_no=?,
            company_license=?, company_name=?, company_server=?, contact=?,
            language=?, query_type=?, query=?, status=?, duration=?, rating=?
        WHERE id=?
    """, (
        data['date'], data['time'], data['agent_name'], data['ticket_no'], data['ref_ticket_no'],
        data['company_license'], data['company_name'], data['company_server'], data['contact'],
        data['language'], data['query_type'], data['query'], data['status'], data['duration'], data['rating'],
        id
    ))
    conn.commit()
    conn.close()
    flash('Ticket updated successfully.', 'success')
    return redirect(url_for('tickets_admin'))


# tickets_admin-Delete Tickets
@app.route('/delete_ticket/<int:id>', methods=['POST'])
@login_required
def delete_ticket(id):
    #id = request.form['id']
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("DELETE FROM call_data WHERE id=?", (id,))
    conn.commit()
    conn.close()
    flash('Ticket Deleted.', 'danger')
    return redirect('/tickets_admin')  # or your view page

# ---------- Manage User (Admin) ----------
# manage_user-Main Page
@app.route("/manage_user")
@login_required
def manage_user():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM users ORDER BY id DESC")
    users = c.fetchall()
    conn.close()
    return render_template("manage_user.html", users=users, username=session["username"], license=session["license"], login_time=session["login_time"])

# manage_user-Add User
@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    data = request.form
    hashed_password = generate_password_hash(data['password'])  # 🔐 Hash the password here
    
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        INSERT INTO users (license, company, username, password, role, status) 
        VALUES (?, ?, ?, ?, ?, ?)
    """, (data['license'], data['company'], data['username'], hashed_password, data['role'], data['status']))
    
    conn.commit()
    conn.close()
    return redirect(url_for('manage_user'))

# manage_user-Update User
@app.route('/update_user/<int:id>', methods=['POST'])
@login_required
def update_user(id):
    data = request.form
    new_password = data['password']
    
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    if new_password.strip():  # Only update password if field is filled
        hashed_pw = generate_password_hash(new_password)
        c.execute("""
            UPDATE users 
            SET license=?, company=?, username=?, password=?, role=?, status=?
            WHERE id=?
        """, (data['license'], data['company'], data['username'], hashed_pw, data['role'], data['status'], id))
    else:
        c.execute("""
            UPDATE users 
            SET license=?, company=?, username=?, role=?, status=?
            WHERE id=?
        """, (data['license'], data['company'], data['username'], data['role'], data['status'], id))

    conn.commit()
    conn.close()
    return redirect(url_for('manage_user'))

# manage_user-Delete User
@app.route('/delete_user/<int:id>')
@login_required
def delete_user(id):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('manage_user'))

# manage_user-Download CSV File
@app.route('/download_csv')
@login_required
def download_csv():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT license, company, username, role, status FROM users")
    data = c.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['License', 'Company', 'Username', 'Role', 'Status'])
    writer.writerows(data)

    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv',
                     download_name=f'users_{datetime.now().strftime("%Y%m%d%H%M%S")}.csv', as_attachment=True)




# ------------- Company List (Admin) ----------------------
# company_list-Main Page
@app.route('/company_list')
@login_required
def company_list():
    conn = get_db()
    rows = conn.execute("SELECT * FROM company_list ORDER BY company_license DESC").fetchall()
    return render_template('company_list.html',
                           license=session.get('license'),
                           username=session.get('username'),
                           company_list=rows)


@app.route('/add_company', methods=['POST'])
@login_required
def add_company():
    data = request.form
    
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        INSERT INTO company_list (company_license, company_name, company_server) 
        VALUES (?, ?, ?)
    """, (data['company_license'], data['company_name'], data['company_server']))
    
    conn.commit()
    conn.close()
    return redirect(url_for('company_list'))


@app.route('/download_company_list')
@login_required
def download_company_list():
    conn = get_db()
    rows = conn.execute("SELECT * FROM company_list").fetchall()

    # Step 1: Write CSV data to StringIO (text)
    output = io.StringIO()
    writer = csv.writer(output)

    if rows:
        writer.writerow(rows[0].keys())  # headers
        for row in rows:
            writer.writerow(row)

    # Step 2: Convert text to BytesIO (binary)
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8'))
    mem.seek(0)
    output.close()

    # Step 3: Send as downloadable file
    return send_file(mem,
                     mimetype='text/csv',
                     as_attachment=True,
                     download_name='company_list.csv')

# tickets_admin-Edit Tickets
@app.route('/edit_company', methods=['POST'])
@login_required
def edit_company():
    id = request.form['id']
    company_license = request.form['company_license']
    company_name = request.form['company_name']
    company_server = request.form['company_server']

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""UPDATE company_list SET 
                 company_license=?, company_name=?, company_server=? 
                 WHERE id=?""",
              (company_license, company_name, company_server, id))
    conn.commit()
    conn.close()
    return redirect('/company_list')


# tickets_admin-Delete Tickets
@app.route('/delete_company', methods=['POST'])
@login_required
def delete_company():
    id = request.form['id']
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("DELETE FROM company_list WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect('/company_list')  # or your view page


@app.route('/upload_company_list', methods=['POST'])
@login_required
def upload_company_list():
    file = request.files.get('file')

    if not file or file.filename == '':
        flash('No file selected!', 'danger')
        return redirect(url_for('company_list'))

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        # Read Excel or CSV based on file extension
        if filename.endswith('.xlsx'):
            df = pd.read_excel(filepath)
        elif filename.endswith('.csv'):
            df = pd.read_csv(filepath)
        else:
            flash("Invalid file type. Please upload .xlsx or .csv", "danger")
            return redirect(url_for('company_list'))

        # Normalize column names
        df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")

        required_columns = {'company_license', 'company_name', 'company_server'}
        if not required_columns.issubset(df.columns):
            flash('❌ Invalid file format. Required columns: company_license, company_name, company_server', 'danger')
            return redirect(url_for('company_list'))

        # Connect DB and insert/update
        conn = sqlite3.connect(DB)
        cursor = conn.cursor()

        for _, row in df.iterrows():
            cursor.execute("""
                INSERT INTO company_list (company_license, company_name, company_server)
                VALUES (?, ?, ?)
                ON CONFLICT(company_license) DO UPDATE SET
                    company_name=excluded.company_name,
                    company_server=excluded.company_server
            """, (row['company_license'], row['company_name'], row['company_server']))

        conn.commit()
        conn.close()
        flash('✅ Company list uploaded successfully!', 'success')

    except Exception as e:
        flash(f'❌ Upload failed: {str(e)}', 'danger')

    return redirect(url_for('company_list'))
# ---------- Auto Backup ----------

@app.route('/download_backup')
@login_required
def download_backup():
    # Ensure backups folder exists
    if not os.path.exists('backups'):
        os.makedirs('backups')

    # Generate timestamped filename
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"data_backup_{timestamp}.db"
    backup_path = os.path.join('backups', filename)

    # Copy the database
    shutil.copy(DB, backup_path)

    # Log backup history
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        INSERT INTO backup_history (filename, backup_date, username)
        VALUES (?, ?, ?)
    """, (
        filename,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        session['username']
    ))
    conn.commit()
    conn.close()

    # Send file for download
    return send_file(backup_path, as_attachment=True)



@app.route('/backup_history')
@login_required
def backup_history():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT filename, backup_date, username FROM backup_history ORDER BY id DESC")
    history = [{'filename': row[0], 'backup_date': row[1], 'username': row[2]} for row in c.fetchall()]
    conn.close()
    return render_template('backup_history.html', license=session.get('license'), username=session.get('username'), history=history)


# ---------- Run App ----------
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
