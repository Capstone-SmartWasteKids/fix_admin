from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
import os
from werkzeug.utils import secure_filename
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import base64
from functools import wraps
from datetime import timedelta
from flask import request

# 1. Import Config dari file config.py
from config import Config 

app = Flask(__name__)

# 2. Muat konfigurasi dari Class Config
app.config.from_object(Config)
app.config['SESSION_PERMANENT'] = False
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # True kalau pakai HTTPS
    SESSION_COOKIE_SAMESITE='Lax'
)

# Konfigurasi Upload Folder (Wajib ada karena DB baru menyimpan Path, bukan BLOB)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Inisialisasi MySQL
mysql = MySQL(app)
def master_admin_exists():
    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) AS total FROM users WHERE role = 'master_admin'")
    result = cur.fetchone()
    cur.close()
    return result['total'] > 0

# =========================
# ACTIVITY LOG HELPER
# =========================
def log_activity(activity):
    if current_user.is_authenticated:
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO activity_logs (admin_id, activity)
            VALUES (%s, %s)
        """, (current_user.id, activity))
        mysql.connection.commit()
        cur.close()

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(403)

            if current_user.role not in roles:
                flash("Anda tidak memiliki hak akses ke halaman ini.", "danger")
                return redirect(url_for('dashboard'))

            return f(*args, **kwargs)
        return wrapper
    return decorator


# --- INISIALISASI FLASK-LOGIN ---
login_manager = LoginManager(app)
login_manager.login_view = 'login' 
login_manager.login_message = "Silakan login untuk mengakses halaman ini."
login_manager.login_message_category = "warning"

# --- CLASS USER ---
class User(UserMixin):
    def __init__(
        self,
        user_id,
        username,
        role,
        avatar=None,
        email=None,
        full_name=None
    ):
        self.id = user_id          # WAJIB utk Flask-Login
        self.user_id = user_id
        self.username = username
        self.role = role
        self.avatar = avatar
        self.email = email
        self.full_name = full_name


# --- USER LOADER ---
@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT
            user_id,
            username,
            role,
            avatar,
            email,
            full_name
        FROM users
        WHERE user_id = %s
    """, (user_id,))
    user = cur.fetchone()
    cur.close()

    if user:
        return User(
            user['user_id'],
            user['username'],
            user['role'],
            user['avatar'],
            user['email'],
            user['full_name']
        )
    return None

# --- ROUTES ---

@app.route('/')
@login_required
def dashboard():
    cur = mysql.connection.cursor()

    # STAT CARD
    cur.execute("SELECT COUNT(*) total FROM users")
    total_users = cur.fetchone()['total']

    cur.execute("SELECT COUNT(*) total FROM educational_contents")
    total_edukasi = cur.fetchone()['total']


    cur.execute("SELECT COUNT(*) total FROM waste_categories")
    total_kategori = cur.fetchone()['total']

    # GRAFIK 1: USER PER ROLE
    cur.execute("""
        SELECT role, COUNT(*) total
        FROM users
        GROUP BY role
    """)
    users_role = cur.fetchall()

    # GRAFIK 2: SAMPAH PER KATEGORI
    cur.execute("""
        SELECT c.name kategori, COUNT(w.id) total
        FROM waste_categories c
        LEFT JOIN waste_items w ON c.id = w.category_id
        GROUP BY c.id
    """)
    sampah_kategori = cur.fetchall()

    # GRAFIK 3: AKTIVITAS PER HARI (7 hari terakhir)
    cur.execute("""
        SELECT DATE(created_at) tanggal, COUNT(*) total
        FROM activity_logs
        WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
        GROUP BY DATE(created_at)
    """)
    aktivitas_harian = cur.fetchall()

    cur.close()

    return render_template(
        'dashboard.html',
        total_users=total_users,
        total_edukasi=total_edukasi,
        total_kategori=total_kategori,
        users_role=users_role,
        sampah_kategori=sampah_kategori,
        aktivitas_harian=aktivitas_harian
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        cur = mysql.connection.cursor()
        # QUERY UPDATE: users
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        account = cur.fetchone()
        cur.close()

        if account:
            # Note: File SQL menggunakan scrypt, tapi disini kita pakai generate_password_hash (pbkdf2)
            # User dari dump SQL mungkin tidak bisa login jika algoritma hash beda.
            # Kode ini cocok untuk user baru yang dibuat lewat web ini.
            if check_password_hash(account['password'], password):
                if account['role'] in ['admin', 'master_admin']:
                    user_obj = User(account['user_id'], account['username'], account['role'])
                    session.permanent = False
                    login_user(user_obj, remember=False)
                    log_activity("Login ke sistem")
                    flash('Login berhasil! Selamat datang.', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Username salah atau Anda tidak memiliki akses Admin.', 'danger')
            else:
                flash('Username atau Password salah.', 'danger')
        else:
            flash('Username salah.', 'danger')

    return render_template(
        'login.html',
        master_admin_exists=master_admin_exists()
    )

@app.route('/register-master-admin')
def register_master_admin():
    if master_admin_exists():
        flash('Master Admin sudah terdaftar.', 'warning')
        return redirect(url_for('login'))
    return render_template('register_master_admin.html')

@app.route('/register-master-admin/save', methods=['POST'])
def save_master_admin():
    if master_admin_exists():
        flash('Master Admin sudah ada. Tidak bisa menambahkan lagi.', 'danger')
        return redirect(url_for('login'))

    username = request.form['username']
    email = request.form['email']
    password = generate_password_hash(request.form['password'])

    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO users (username, email, password, role)
        VALUES (%s,%s,%s,'master_admin')
    """, (username, email, password))

    mysql.connection.commit()
    cur.close()

    flash('Master Admin berhasil dibuat. Silakan login.', 'success')
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    log_activity("Logout dari sistem")
    logout_user() 
    session.clear()
    flash('Anda telah logout.', 'success')
    return redirect(url_for('login'))

@app.route('/users')
@login_required
@role_required('admin', 'master_admin')
def users():
    cur = mysql.connection.cursor()
    # QUERY UPDATE: users (user_id)
    cur.execute("""
        SELECT *
        FROM users
        ORDER BY user_id DESC
    """)
    users_data = cur.fetchall()
    cur.close()
    return render_template('users.html', users=users_data)


# =========================
# FORM TAMBAH USER
# =========================
@app.route('/user/add')
@login_required
@role_required('admin', 'master_admin')
def add_user_form():
    # Tabel 'level_user' tidak ada di file SQL baru.
    # Level sepertinya hardcoded di enum atau string biasa ('Pemula', 'Legendaris', dll).
    # Kita kirim list manual saja.
    levels = [{'nama_level': 'Pemula'}, {'nama_level': 'Menengah'}, {'nama_level': 'Ahli'}, {'nama_level': 'Legendaris'}]
    return render_template('form_user.html', user=None, levels=levels)


# =========================
# FORM EDIT USER
# =========================
@app.route('/user/edit/<string:id_user>')
@login_required
@role_required('admin', 'master_admin')
def edit_user_form(id_user):
    cur = mysql.connection.cursor()
    # QUERY UPDATE: users (user_id)
    cur.execute("SELECT * FROM users WHERE user_id=%s", (id_user,))
    user_data = cur.fetchone()
    cur.close()

    levels = [{'nama_level': 'Pemula'}, {'nama_level': 'Menengah'}, {'nama_level': 'Ahli'}, {'nama_level': 'Legendaris'}]

    if not user_data:
        flash('User tidak ditemukan', 'danger')
        return redirect(url_for('users'))

    # Handling gambar untuk edit (Karena sekarang path, bukan blob)
    # Anda mungkin perlu menyesuaikan template HTML untuk menampilkan gambar dari path
    user_data['foto_path'] = user_data['avatar'] 

    return render_template('form_user.html', user=user_data, levels=levels)



# =========================
# SAVE USER (INSERT & UPDATE)
# =========================
@app.route('/user/save', methods=['POST'])
def save_user():
    id_user = request.form.get('id_users') # Pastikan name di HTML adalah id_users atau sesuaikan
    nama = request.form['nama_lengkap']
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']
    level = request.form['level']

    # HANDLING FILE (Menyimpan Nama File ke DB, File Fisik ke Folder)
    foto = request.files.get('foto_profile')
    filename = None
    
    if foto and foto.filename:
        filename = secure_filename(foto.filename)
        foto.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    else:
        # Set default avatar jika user baru dan tidak upload foto
        if not id_user: 
            filename = 'default_avatar.png'

    cur = mysql.connection.cursor()

    try:
        # INSERT
        if not id_user:
            hashed_pw = generate_password_hash(password)

            # QUERY UPDATE: menyesuaikan kolom tabel users yang baru
            # kolom: full_name, username, email, password, role, level, avatar
            cur.execute("""
                INSERT INTO users
                (full_name, username, email, password, role, level, avatar)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (nama, username, email, hashed_pw, role, level, filename))

            flash('Pengguna berhasil ditambahkan', 'success')
            mysql.connection.commit()
            log_activity(f"Menambahkan user baru: {username}")

        # UPDATE
        else:
            query_pass = ""
            # Kolom di DB: full_name, username, email, role, level
            params = [nama, username, email, role, level]

            if password:
                hashed_pw = generate_password_hash(password)
                query_pass += ", password=%s"
                params.append(hashed_pw)

            if filename:
                query_pass += ", avatar=%s" # Update kolom avatar
                params.append(filename)

            params.append(id_user)

            # QUERY UPDATE: users (user_id)
            cur.execute(f"""
                UPDATE users SET
                full_name=%s,
                username=%s,
                email=%s,
                role=%s,
                level=%s
                {query_pass}
                WHERE user_id=%s
            """, tuple(params))

            flash('Data pengguna berhasil diperbarui', 'success')

        mysql.connection.commit()
        log_activity(f"Mengubah data user ID {id_user}")

    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error: {e}', 'danger')

    finally:
        cur.close()

    return redirect(url_for('users'))


@app.route('/delete_user/<string:id_user>')
@login_required
@role_required('master_admin')
def delete_user(id_user):
    cur = mysql.connection.cursor()

    cur.execute("SELECT role FROM users WHERE user_id=%s", (id_user,))
    target = cur.fetchone()

    if not target:
        flash("User tidak ditemukan", "warning")
        return redirect(url_for('users'))

    if target['role'] == 'master_admin':
        flash("Master Admin tidak boleh dihapus!", "danger")
        return redirect(url_for('users'))

    cur.execute("DELETE FROM users WHERE user_id=%s", (id_user,))
    mysql.connection.commit()

    log_activity(f"Menghapus user ID {id_user}")
    flash("User berhasil dihapus", "success")

    cur.close()
    return redirect(url_for('users'))

# =========================
# LIST SAMPAH
# =========================
@app.route('/sampah')
def sampah():
    cur = mysql.connection.cursor()
    # QUERY UPDATE: waste_items & waste_categories
    # Kolom: id, name, category_id, description, decomposition_time, benefits, image_sample
    cur.execute("""
        SELECT
            w.id,
            w.name AS nama_sampah,
            w.decomposition_time AS lama_terurai,
            w.description AS deskripsi_sampah,
            w.benefits AS manfaat_sampah,
            w.image_sample,
            c.name AS jenis_sampah
        FROM waste_items w
        LEFT JOIN waste_categories c
            ON w.category_id = c.id
        ORDER BY w.id DESC
    """)
    sampah = cur.fetchall()



    # Tidak perlu konversi Base64 lagi karena DB menyimpan Path
    # Di HTML nanti panggil: <img src="{{ url_for('static', filename='uploads/' + row['image_sample']) }}">
    
    cur.close()
    return render_template('sampah.html', sampah=sampah)


# =========================
# FORM TAMBAH SAMPAH
# =========================
@app.route('/sampah/add')
def add_sampah():
    cur = mysql.connection.cursor()
    # QUERY UPDATE: waste_categories
    cur.execute("SELECT * FROM waste_categories")
    kategori = cur.fetchall()
    cur.close()

    return render_template('form_sampah.html', sampah=None, kategori=kategori)


# =========================
# FORM EDIT SAMPAH
# =========================
@app.route('/sampah/edit/<int:id_sampah>')
def edit_sampah(id_sampah):
    cur = mysql.connection.cursor()

    # QUERY UPDATE: waste_items (id)
    cur.execute("SELECT * FROM waste_items WHERE id=%s", (id_sampah,))
    data = cur.fetchone()

    # QUERY UPDATE: waste_categories
    cur.execute("SELECT * FROM waste_categories")
    kategori = cur.fetchall()
    cur.close()

    return render_template('form_sampah.html', sampah=data, kategori=kategori)


# =========================
# SIMPAN SAMPAH (INSERT & UPDATE)
# =========================
@app.route('/sampah/save', methods=['POST'])
def save_sampah():
    id_sampah = request.form.get('id_sampah')
    nama = request.form['nama_sampah']
    kategori = request.form['id_kategori']
    lama = request.form['lama_terurai']
    deskripsi = request.form['deskripsi_sampah']
    manfaat = request.form['manfaat_sampah']

    # HANDLING FILE (Simpan Path/Filename, bukan BLOB)
    foto = request.files.get('gambar')
    filename = None
    
    if foto and foto.filename:
        filename = secure_filename(foto.filename)
        foto.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    cur = mysql.connection.cursor()

    try:
        if not id_sampah:
            # INSERT
            # QUERY UPDATE: waste_items
            # Kolom: name, category_id, decomposition_time, description, benefits, image_sample
            cur.execute("""
                INSERT INTO waste_items
                (name, category_id, decomposition_time, description, benefits, image_sample)
                VALUES (%s,%s,%s,%s,%s,%s)
            """, (nama, kategori, lama, deskripsi, manfaat, filename))
            flash('Sampah berhasil ditambahkan', 'success')
            mysql.connection.commit()
            log_activity(f"Menambahkan data sampah: {nama}")

        else:
            # UPDATE
            # QUERY UPDATE: waste_items
            sql = """
                UPDATE waste_items SET
                name=%s,
                category_id=%s,
                decomposition_time=%s,
                description=%s,
                benefits=%s
            """
            params = [nama, kategori, lama, deskripsi, manfaat]

            if filename:
                sql += ", image_sample=%s" # Kolom baru: image_sample
                params.append(filename)

            sql += " WHERE id=%s" # PK baru: id
            params.append(id_sampah)

            cur.execute(sql, tuple(params))
            flash('Data sampah berhasil diperbarui', 'success')

        mysql.connection.commit()

    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error: {e}', 'danger')

    finally:
        cur.close()

    return redirect(url_for('sampah'))

# =========================
# DELETE SAMPAH
# =========================
@app.route('/sampah/delete/<int:id_sampah>')
def delete_sampah(id_sampah):
    cur = mysql.connection.cursor()
    try:
        # Cek data dulu
        cur.execute("SELECT * FROM waste_items WHERE id = %s", (id_sampah,))
        data = cur.fetchone()

        if not data:
            flash('Data sampah tidak ditemukan!', 'warning')
            return redirect(url_for('sampah'))

        # Hapus data
        cur.execute("DELETE FROM waste_items WHERE id = %s", (id_sampah,))
        mysql.connection.commit()

        flash('Data sampah berhasil dihapus!', 'success')

    except Exception as e:
        mysql.connection.rollback()
        flash(f'Gagal menghapus data: {e}', 'danger')

    finally:
        cur.close()

    return redirect(url_for('sampah'))


@app.route('/activity-logs')
@login_required
def activity_logs():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT l.id, l.activity, l.created_at, u.username
        FROM activity_logs l
        JOIN users u ON l.admin_id = u.user_id
        ORDER BY l.created_at DESC
    """)
    logs = cur.fetchall()
    cur.close()

    return render_template('activity_logs.html', logs=logs)

# =========================
# LIST KATEGORI
# =========================
@app.route('/kategori')
@login_required
def kategori():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM waste_categories ORDER BY id DESC")
    kategori = cur.fetchall()
    cur.close()
    return render_template('kategori.html', kategori=kategori)


# =========================
# SIMPAN KATEGORI
# =========================
@app.route('/kategori/save', methods=['POST'])
@login_required
def save_kategori():
    nama = request.form['name']
    deskripsi = request.form['description']

    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO waste_categories (name, description)
        VALUES (%s, %s)
    """, (nama, deskripsi))
    mysql.connection.commit()
    cur.close()

    flash('Kategori berhasil ditambahkan', 'success')
    return redirect(url_for('kategori'))


# =========================
# HAPUS KATEGORI
# =========================
@app.route('/kategori/delete/<int:id>')
@login_required
def delete_kategori(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM waste_categories WHERE id=%s", (id,))
    mysql.connection.commit()
    cur.close()

    flash('Kategori berhasil dihapus', 'success')
    return redirect(url_for('kategori'))


@app.route('/edukasi')
@login_required
def edukasi():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT id, title, content, media_url, content_type, created_at
        FROM educational_contents
        ORDER BY created_at DESC
    """)
    edukasi = cur.fetchall()
    cur.close()

    return render_template('edukasi.html', edukasi=edukasi)

@app.route('/edukasi/add')
@login_required
def add_edukasi():
    return render_template('form_edukasi.html', data=None)


@app.route('/edukasi/save', methods=['POST'])
@login_required
def save_edukasi():
    title = request.form['title']
    content = request.form['content']
    content_type = request.form['content_type']

    file = request.files.get('media')
    filename = None

    if file and file.filename:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO educational_contents
        (title, content, media_url, content_type, created_at)
        VALUES (%s, %s, %s, %s, NOW())
    """, (title, content, filename, content_type))

    mysql.connection.commit()
    cur.close()

    flash('Konten edukasi berhasil ditambahkan', 'success')
    return redirect(url_for('edukasi'))

@app.route('/edukasi/delete/<int:id>')
def delete_edukasi(id):
    cur = mysql.connection.cursor()
    try:
        cur.execute(
            "DELETE FROM educational_contents WHERE id=%s",
            (id,)
        )
        mysql.connection.commit()
        flash('Konten edukasi berhasil dihapus', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Gagal menghapus data: {e}', 'danger')
    finally:
        cur.close()

    return redirect(url_for('edukasi'))



@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    full_name = request.form['full_name']
    username  = request.form['username']
    email     = request.form['email']
    password  = request.form.get('password')

    avatar = request.files.get('avatar')
    filename = current_user.avatar

    if avatar and avatar.filename:
        filename = secure_filename(avatar.filename)
        avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    cur = mysql.connection.cursor()

    try:
        sql = """
            UPDATE users SET
                full_name=%s,
                username=%s,
                email=%s,
                avatar=%s
        """
        params = [full_name, username, email, filename]

        if password:
            hashed = generate_password_hash(password)
            sql += ", password=%s"
            params.append(hashed)

        sql += " WHERE user_id=%s"
        params.append(current_user.id)

        cur.execute(sql, tuple(params))
        mysql.connection.commit()

        flash('Profil berhasil diperbarui', 'success')

    except Exception as e:
        mysql.connection.rollback()
        flash(f'Gagal update profil: {e}', 'danger')

    finally:
        cur.close()

    return redirect(url_for('profile'))

@app.before_request
def protect_admin():
    if current_user.is_authenticated:
        if not session:
            logout_user()

if __name__ == '__main__':
    app.run(debug=True)