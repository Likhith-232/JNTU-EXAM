from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import json
import csv
from io import StringIO
import random
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message
from flask import render_template_string


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('postgresql://jntu_db_user:40OU1X3HaYcu6UU9ak0nMnLZA7LUPb7z@dpg-d2366kre5dus73aagg8g-a.singapore-postgres.render.com/jntu_db
')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'likhithmanakala@gmail.com'
app.config['MAIL_PASSWORD'] = 'rgvvqecqnysxqzeh'
app.config['MAIL_DEFAULT_SENDER'] = 'likhithmanakala@gmail.com'
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
from itsdangerous import URLSafeTimedSerializer

# Setup
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_token(email):
    return serializer.dumps(email, salt='password-reset')

def verify_token(token, max_age=1800):  # 30 minutes expiry
    try:
        return serializer.loads(token, salt='password-reset', max_age=max_age)
    except Exception:
        return None


db = SQLAlchemy(app)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# -------------------- Database Models --------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    roll_no = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    address = db.Column(db.Text, nullable=False)
    branch = db.Column(db.String(50), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    profile_pic = db.Column(db.String(120), default='default.jpg')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
class Exam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    duration_minutes = db.Column(db.Integer)
    total_marks = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

# models.py
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(100), nullable=False)
    option_b = db.Column(db.String(100), nullable=False)
    option_c = db.Column(db.String(100), nullable=False)
    option_d = db.Column(db.String(100), nullable=False)
    correct_answer = db.Column(db.String(1), nullable=False)
    marks = db.Column(db.Integer, nullable=False)


class ExamResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total_marks = db.Column(db.Integer, nullable=False)
    time_taken = db.Column(db.Integer)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    answers = db.Column(db.Text)
user = db.relationship('User', backref='results')
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

# -------------------- Helpers --------------------
def is_logged_in():
    return 'user_id' in session

def is_admin_logged_in():
    return 'admin' in session

def save_profile_pic(file):
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return filename
    return 'default.jpg'

# -------------------- Routes --------------------
@app.route('/')
def index():
    return render_template('index.html')

# ----- Admin Routes -----
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password_hash, password):
            session['admin'] = admin.username
            flash('Logged in successfully as admin', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials', 'error')
    return render_template('admin_login.html')
@app.route('/admin/dashboard')
def admin_dashboard():
    if not is_admin_logged_in():
        return redirect(url_for('admin_login'))

    page = request.args.get('page', 1, type=int)
    per_page = 500

    paginated_results = db.session.query(ExamResult, User, Exam)\
        .join(User, ExamResult.user_id == User.id)\
        .join(Exam, ExamResult.exam_id == Exam.id)\
        .order_by(ExamResult.completed_at.desc())\
        .paginate(page=page, per_page=per_page)

    return render_template('admin_dashboard.html', results=paginated_results)
@app.route('/admin/results/download')
def download_results_csv():
    if not is_admin_logged_in():
        return redirect(url_for('admin_login'))
    results = db.session.query(ExamResult, User, Exam).join(User).join(Exam).all()
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Name', 'Roll No', 'Exam', 'Score', 'Total', 'Date'])
    for result, user, exam in results:
        cw.writerow([
            user.name, user.roll_no, exam.title, result.score,
            result.total_marks, result.completed_at.strftime('%d-%m-%Y %H:%M')
        ])
    output = si.getvalue()
    return Response(
        output,
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=results.csv"}
    )

@app.route('/admin/results/clear', methods=['GET', 'POST'])
def clear_results():
    if not is_admin_logged_in():
        return redirect(url_for('admin_login'))

    # Delete all exam results
    try:
        num_deleted = ExamResult.query.delete()
        db.session.commit()
        flash(f'Successfully deleted {num_deleted} exam results.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to delete exam results: ' + str(e), 'error')

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/users')
def admin_users():
    if not is_admin_logged_in():
        return redirect(url_for('admin_login'))

    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)
@app.route('/admin/leaderboard')
def admin_leaderboard():
    # Allow access without login like /admin/users
    exams = Exam.query.all()
    leaderboard_data = []

    for exam in exams:
        # Get all results for this exam, ordered by score desc and time asc
        results = ExamResult.query.filter_by(exam_id=exam.id)\
                    .order_by(ExamResult.score.desc(), ExamResult.completed_at.asc()).all()

        leaderboard_entries = []
        rank = 1
        prev_score = None
        display_rank = 1

        for i, res in enumerate(results):
            if prev_score is None or res.score != prev_score:
                display_rank = rank
            # If same score, same rank as before

            leaderboard_entries.append({
                'rank': display_rank,
                'name': res.user.name,
                'roll_number': res.user.roll_number,
                'score': res.score,
                'completed_at': res.completed_at.strftime('%Y-%m-%d %H:%M:%S')
            })

            prev_score = res.score
            rank += 1

        leaderboard_data.append({
            'exam': exam,
            'entries': leaderboard_entries
        })

    return render_template('admin_leaderboard.html', leaderboard=leaderboard_data)


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('admin_login'))

# ----- User Routes -----
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        roll_no = data['roll_no']

        # Validation
        if len(roll_no) != 10 or not roll_no.isalnum():
            flash("Roll number must be exactly 10 alphanumeric characters.", "error")
            return render_template('register.html')

        if User.query.filter_by(email=data['email']).first():
            flash('Email already registered', 'error')
            return render_template('register.html')

        if User.query.filter_by(roll_no=roll_no).first():
            flash('Roll number already registered', 'error')
            return render_template('register.html')

        if len(data['password']) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('register.html')

        file = request.files.get('profile_pic')
        profile_pic = save_profile_pic(file)

        user = User(
            name=data['name'],
            roll_no=roll_no,
            email=data['email'],
            phone_number=data['phone_number'],
            address=data['address'],
            branch=data['branch'],
            gender=data['gender'],
            password_hash=generate_password_hash(data['password']),
            profile_pic=profile_pic
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        roll_no = request.form['roll_no']
        password = request.form['password']
        user = User.query.filter_by(roll_no=roll_no).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid roll number or password', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if not is_logged_in():
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    # TEMP DEBUG: Get all exams (without filtering by is_active)
    exams = Exam.query.order_by(Exam.id).all()

    # DEBUG OUTPUT - Show all exams in console
    print("=== Exams from DB ===")
    for exam in exams:
        print(f"ID: {exam.id}, Title: {exam.title}, is_active: {getattr(exam, 'is_active', 'N/A')}")

    # Fetch user's results
    results = ExamResult.query.filter_by(user_id=user.id).all()

    total_exams = len(exams)
    completed_exams = len(results)
    avg_score = sum(r.score for r in results) / len(results) if results else 0

    progress_stats = {
        'total_exams': total_exams,
        'completed_exams': completed_exams,
        'avg_score': round(avg_score, 1),
        'completion_rate': round((completed_exams / total_exams * 100) if total_exams > 0 else 0, 1)
    }

    # Clear submitted flag after use
    session.pop('exam_submitted', None)

    return render_template(
        'dashboard.html',
        user=user,
        exams=exams,
        results=results,
        progress_stats=progress_stats
    )

@app.route('/exam/<int:exam_id>', methods=['GET'])
def take_exam(exam_id):
    if not is_logged_in():
        return redirect(url_for('login'))

    existing_result = ExamResult.query.filter_by(user_id=session['user_id'], exam_id=exam_id).first()
    if existing_result:
        flash("You have already taken this exam.", "info")
        return redirect(url_for('results'))

    exam = Exam.query.get_or_404(exam_id)
    questions = Question.query.filter_by(exam_id=exam_id).all()

    return render_template('exam.html', exam=exam, questions=questions,
                           current_question=1, total_questions=len(questions))
@app.route('/submit_exam', methods=['POST'])
def submit_exam():
    if not is_logged_in():
        return redirect(url_for('login'))

    data = request.json
    exam_id = data.get('exam_id')
    answers = data.get('answers', {})
    time_taken = data.get('time_taken')

    submitted_exams = session.get('submitted_exams', [])
    if str(exam_id) in submitted_exams:
        return jsonify({'success': False, 'message': 'You already submitted this exam'})

    exam = Exam.query.get_or_404(exam_id)
    questions = Question.query.filter_by(exam_id=exam_id).all()

    score = 0
    correct_answers_count = 0
    wrong_answers_count = 0

    for question in questions:
        user_answer = answers.get(str(question.id))
        if user_answer == question.correct_answer:
            score += question.marks
            correct_answers_count += 1
        else:
            wrong_answers_count += 1

    result = ExamResult(
        user_id=session['user_id'],
        exam_id=exam_id,
        score=score,
        total_marks=exam.total_marks,
        time_taken=time_taken,
        answers=json.dumps(answers)
    )
    db.session.add(result)
    db.session.commit()

    # ✅ Mark this exam as submitted in session
    submitted_exams.append(str(exam_id))
    session['submitted_exams'] = submitted_exams

    return jsonify({
        'success': True,
        'score': score,
        'total_marks': exam.total_marks,
        'correct': correct_answers_count,
        'wrong': wrong_answers_count,
        'exam_id': exam_id
    })


@app.route('/result_summary')
def result_summary():
    score = int(request.args.get('score', 0))
    total = int(request.args.get('total', 0))
    correct = int(request.args.get('correct', 0))
    wrong = int(request.args.get('wrong', 0))
    return render_template("result_summary.html", score=score, total=total, correct=correct, wrong=wrong)


@app.route('/results')
def results():
    if not is_logged_in():
        return redirect(url_for('login'))

    user_results = db.session.query(ExamResult, Exam)\
        .join(Exam).filter(ExamResult.user_id == session['user_id']).all()
    return render_template('results.html', user_results=user_results)

@app.route('/profile')
def profile():
    if not is_logged_in():
        flash("Please log in to view profile", "error")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    results = db.session.query(ExamResult, Exam)\
        .join(Exam).filter(ExamResult.user_id == user.id).all()
    return render_template('profile.html', user=user, results=results)
@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if not is_logged_in():
        flash("Please log in to edit your profile", "error")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        new_email = request.form.get('email')
        new_phone = request.form.get('phone_number')
        new_address = request.form.get('address')

        # Optional: Check for email uniqueness
        if User.query.filter(User.email == new_email, User.id != user.id).first():
            flash("Email already in use", "error")
            return render_template('edit_profile.html', user=user)

        user.email = new_email
        user.phone_number = new_phone
        user.address = new_address

        db.session.commit()
        flash("Profile updated successfully", "success")
        return redirect(url_for('profile'))

    return render_template('edit_profile.html', user=user)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_token(email)
            reset_url = url_for('reset_password', token=token, _external=True)
            send_reset_email(email, reset_url)
            flash('If this email is registered, a reset link has been sent.', 'info')
        else:
            flash('Email not found!', 'danger')
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_token(token)
    if not email:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        user = User.query.filter_by(email=email).first()
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash('Password reset successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/init_db')
def init_db_route():
    db.create_all()
    return "Database initialized!"

@app.route('/check_db')
def check_db():
    try:
        user_count = User.query.count()
        return f"Connected! Total users in DB: {user_count}"
    except Exception as e:
        return f"Database connection failed: {e}"

def send_reset_email(email, reset_url):
    subject = "🔐 Password Reset Request"
    sender = "likhithmanakala@gmail.com"  # Set your sender email

    # HTML version
    html_body = render_template_string("""
    <html>
      <body style="font-family: 'Segoe UI', sans-serif; color: #333; background-color: #f9f9f9; padding: 30px;">
        <div style="max-width: 600px; margin: auto; background: #fff; border-radius: 8px; padding: 30px; box-shadow: 0 5px 15px rgba(0,0,0,0.1);">
          <h2 style="color: #10b981;">Reset Your Password</h2>
          <p>Hello,</p>
          <p>We received a request to reset the password associated with this email address.</p>
          <p>If you made this request, please click the button below to reset your password:</p>
          <p style="text-align: center; margin: 30px 0;">
            <a href="{{ reset_url }}" style="background: #10b981; color: white; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: bold;">Reset Password</a>
          </p>
          <p>This link will expire in <strong>30 minutes</strong>.</p>
          <p>If you did not request this, you can safely ignore this email.</p>
          <br />
          <p style="font-size: 0.9rem; color: #888;">Thanks,<br>Your Website Team</p>
        </div>
      </body>
    </html>
    """, reset_url=reset_url)

    # Plain text version (fallback)
    text_body = f"""Hello,

We received a request to reset your password.

To reset it, please click the following link:
{reset_url}

This link will expire in 30 minutes.

If you did not request this, please ignore this email.

Thanks,
Your Website Team
"""

    # Send message
    msg = Message(subject, recipients=[email])
    msg.body = text_body
    msg.html = html_body
    msg.sender = sender

    mail.send(msg)




# -------------------- Initial DB Seeder --------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        if not Admin.query.first():
            admin = Admin(username='admin', password_hash=generate_password_hash('admin123'))
            db.session.add(admin)
            db.session.commit()

    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

