import os
import uuid
from functools import wraps
from flask import Flask, render_template, redirect, url_for, request, flash, session, abort
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

# --- App Setup ---
app = Flask(__name__, template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY', 'supersecret')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max file size

# Allowed extensions for uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20))
    house_number = db.Column(db.String(20))
    profile_photo = db.Column(db.String(300))
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.email}>'

class Skill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    skill = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    certificate = db.Column(db.String(300))
    verified = db.Column(db.Boolean, default=False)

    # Add this line:
    user = db.relationship('User', backref=db.backref('skills', lazy=True))

    def __repr__(self):
        return f'<Skill {self.skill} by User {self.user_id}>'


class Tool(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    image = db.Column(db.String(300))

    def __repr__(self):
        return f'<Tool {self.name} by User {self.user_id}>'

# --- Helpers ---
@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    return dict(current_user=user)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = User.query.get(session.get('user_id'))
        if not user or not user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            return redirect(url_for('home'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Prevent duplicate email
        if User.query.filter_by(email=request.form['email']).first():
            flash('Email already registered.')
            return redirect(url_for('register'))

        file = request.files.get('profile_photo')
        if not file or not allowed_file(file.filename):
            flash('Please upload a valid image (png, jpg, jpeg).')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        unique_name = f"{uuid.uuid4().hex}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_name))

        user = User(
            name=request.form['name'],
            email=request.form['email'],
            password=generate_password_hash(request.form['password']),
            phone=request.form['phone'],
            house_number=request.form['house_number'],
            profile_photo=unique_name
        )
        db.session.add(user)
        db.session.commit()
        session['user_id'] = user.id
        return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.')
    return redirect(url_for('home'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('profile.html')

@app.route('/add-skill', methods=['GET', 'POST'])
def add_skill():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files.get('certificate')
        if not file or not allowed_file(file.filename):
            flash('Please upload a valid file (png, jpg, jpeg, pdf).')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        unique_name = f"{uuid.uuid4().hex}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_name))

        skill = Skill(
            user_id=session['user_id'],
            skill=request.form['skill'],
            description=request.form['description'],
            certificate=unique_name
        )
        db.session.add(skill)
        db.session.commit()
        flash('Skill added.')
    return render_template('add_skill.html')

@app.route('/view-skills', methods=['GET', 'POST'])
def view_skills():
    search = request.form.get('search', '')
    if search:
        skills = Skill.query.filter(Skill.skill.ilike(f'%{search}%')).all()
    else:
        skills = Skill.query.all()
    
    user_id = session.get('user_id')  # Add this line
    return render_template('view_skills.html', skills=skills, user_id=user_id)


@app.route('/delete-skill/<int:id>', methods=['POST'])
def delete_skill(id):
    skill = Skill.query.get_or_404(id)
    if skill.user_id != session.get('user_id'):
        abort(403)
    db.session.delete(skill)
    db.session.commit()
    flash('Skill deleted.')
    return redirect(url_for('view_skills'))

@app.route('/add-tool', methods=['GET', 'POST'])
def add_tool():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files.get('image')
        if not file or not allowed_file(file.filename):
            flash('Please upload a valid image (png, jpg, jpeg).')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        unique_name = f"{uuid.uuid4().hex}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_name))

        tool = Tool(
            user_id=session['user_id'],
            name=request.form['name'],
            description=request.form['description'],
            image=unique_name
        )
        db.session.add(tool)
        db.session.commit()
        flash('Tool added.')
    return render_template('add_tool.html')

@app.route('/view-tools', methods=['GET', 'POST'])
def view_tools():
    search = request.form.get('search', '')
    if search:
        tools = Tool.query.filter(Tool.name.ilike(f'%{search}%')).all()
    else:
        tools = Tool.query.all()
    return render_template('view_tools.html', tools=tools)

@app.route('/delete-tool/<int:id>', methods=['POST'])
def delete_tool(id):
    tool = Tool.query.get_or_404(id)
    if tool.user_id != session.get('user_id'):
        abort(403)
    db.session.delete(tool)
    db.session.commit()
    flash('Tool deleted.')
    return redirect(url_for('view_tools'))

@app.route('/admin-dashboard')
@admin_required
def admin_dashboard():
    certificate_requests = db.session.query(Skill, User).join(User).all()
    return render_template('admin.html', certificate_requests=certificate_requests)

@app.route('/verify-certificate/<int:skill_id>', methods=['POST'])
@admin_required
def verify_certificate(skill_id):
    skill = Skill.query.get_or_404(skill_id)
    skill.verified = True
    db.session.commit()
    flash(f"Skill '{skill.skill}' has been verified.")
    return redirect(url_for('admin_dashboard'))

# --- Init & Run ---
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
