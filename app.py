from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
from werkzeug.utils import secure_filename
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import base64

# 1. Import Config dari file config.py
from config import Config 

app = Flask(__name__)

# 2. Muat konfigurasi dari Class Config
app.config.from_object(Config)

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


# --- INISIALISASI FLASK-LOGIN ---
login_manager = LoginManager(app)
login_manager.login_view = 'login' 
login_manager.login_message = "Silakan login untuk mengakses halaman ini."
login_manager.login_message_category = "warning"

# --- CLASS USER ---
class User(UserMixin):
    def __init__(self, user_id, username, role):
        self.id = user_id # Flask-Login butuh properti 'id'
        self.username = username
        self.role = role

# --- USER LOADER ---
@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    # QUERY UPDATE: users (user_id)
    cur.execute("SELECT user_id, username, role FROM users WHERE user_id = %s", (user_id,))
    account = cur.fetchone()
    cur.close()
    
    if account:
        # account['user_id'] sesuai nama kolom baru
        return User(account['user_id'], account['username'], account['role'])
    return None

# --- ROUTES ---

@app.route('/')
@login_required
def dashboard():
    cur = mysql.connection.cursor()

    cur.execute("SELECT COUNT(*) AS total FROM users")
    total_users = cur.fetchone()['total']

    cur.execute("SELECT COUNT(*) AS total FROM educational_contents")
    total_edukasi = cur.fetchone()['total']

    cur.execute("SELECT COUNT(*) AS total FROM waste_categories")
    total_kategori = cur.fetchone()['total']

    cur.close()

    return render_template(
        'dashboard.html',
        admin=current_user,
        total_users=total_users,
        total_edukasi=total_edukasi,
        total_kategori=total_kategori
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
                    login_user(user_obj, remember=True)
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
    logout_user() 
    flash('Anda telah logout.', 'success')
    return redirect(url_for('login'))

@app.route('/users')
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
    level = request.form['current_level']

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

    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error: {e}', 'danger')

    finally:
        cur.close()

    return redirect(url_for('users'))


@app.route('/delete_user/<string:id_user>', methods=['GET'])
def delete_user(id_user):
    cur = mysql.connection.cursor()
    try:
        # QUERY UPDATE: user_id
        cur.execute("SELECT * FROM users WHERE user_id = %s", (id_user,))
        data = cur.fetchone()
        
        if not data:
            flash('Data pengguna tidak ditemukan!', 'warning')
            return redirect(url_for('users'))

        # QUERY UPDATE: user_id
        cur.execute("DELETE FROM users WHERE user_id = %s", (id_user,))
        mysql.connection.commit()
        
        if cur.rowcount > 0:
            flash('Data pengguna berhasil dihapus!', 'success')
        else:
            flash('Gagal menghapus data.', 'danger')

    except Exception as e:
        mysql.connection.rollback()
        flash(f'Terjadi kesalahan sistem: {e}', 'danger')
        
    finally:
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
        SELECT w.*, c.name as jenis_sampah
        FROM waste_items w
        LEFT JOIN waste_categories c
        ON w.category_id = c.id
        ORDER BY w.id DESC
    """)
    data = cur.fetchall()

    # Tidak perlu konversi Base64 lagi karena DB menyimpan Path
    # Di HTML nanti panggil: <img src="{{ url_for('static', filename='uploads/' + row['image_sample']) }}">
    
    cur.close()
    return render_template('sampah.html', sampah=data)


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


if __name__ == '__main__':
    app.run(debug=True)