from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change to a strong secret key

# Ensure the uploads directory exists
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Dummy database
users_db = {}
uploads = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        full_name = request.form['full_name']
        father_name = request.form.get('father_name')
        class_ = request.form.get('class')
        section = request.form.get('section')
        roll_number = request.form.get('roll_number')
        date_of_birth = request.form.get('date_of_birth')
        gender = request.form.get('gender')

        if email in users_db:
            flash('Email already registered. Please log in or use "Forgot Password" to reset your password.', 'error')
            return redirect(url_for('login'))

        users_db[email] = {
            'password': password,
            'full_name': full_name,
            'father_name': father_name,
            'class': class_,
            'section': section,
            'roll_number': roll_number,
            'date_of_birth': date_of_birth,
            'gender': gender
        }
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = users_db.get(email)
        if user and check_password_hash(user['password'], password):
            session['user_email'] = email
            flash('Logged in successfully.')
            return redirect(url_for('dashboard'))

        flash('Invalid email or password.')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        # Logic to send OTP to email would go here
        flash('OTP sent to your email.')
        return redirect(url_for('verify_otp'))

    return render_template('forgot_password.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        # Logic to verify OTP would go here
        flash('OTP verified. Please reset your password.')
        return redirect(url_for('reset_password'))

    return render_template('verify_otp.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        otp = request.form['otp']
        new_password = generate_password_hash(request.form['new_password'])
        # Logic to reset password would go here
        flash('Password reset successfully. Please log in.')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/dashboard')
def dashboard():
    if 'user_email' not in session:
        flash('Please log in first.')
        return redirect(url_for('login'))

    user_email = session['user_email']
    user = users_db[user_email]
    user_uploads = [file for file in uploads if file['user'] == user_email]
    return render_template('dashboard.html', user=user, uploads=user_uploads)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_email' not in session:
        flash('Please log in first.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        if file:
            file.save(os.path.join(UPLOAD_FOLDER, file.filename))
            uploads.append({'filename': file.filename, 'user': session['user_email']})
            flash('File uploaded successfully.')
            return redirect(url_for('dashboard'))

    return render_template('uploads.html')

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    flash('Logged out successfully.')
    return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/delete/<filename>')
def delete_file(filename):
    if 'user_email' not in session:
        flash('Please log in first.')
        return redirect(url_for('login'))

    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        global uploads
        uploads = [file for file in uploads if file['filename'] != filename or file['user'] != session['user_email']]
        flash(f'{filename} has been deleted.')
    else:
        flash(f'{filename} does not exist.')

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
