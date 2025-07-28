# Flask VDR App with Authentication and Project-Specific Document Management

from flask import Flask, render_template, redirect, url_for, request, flash, session, make_response, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from functools import wraps
from werkzeug.utils import secure_filename
from datetime import datetime
from PyPDF2 import PdfReader
import os, random, string, tempfile, atexit
import logging
from watermark_merger import add_watermark_to_pdf

app = Flask(__name__)
app.config.update(
    SECRET_KEY='super-secret-key',
    SQLALCHEMY_DATABASE_URI='mysql+pymysql://bramston2_vdr:Trilesh_230@64.62.171.47:3306/bramston2_vdr',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    UPLOAD_FOLDER='uploads',
    SQLALCHEMY_ENGINE_OPTIONS={
        'pool_pre_ping': True,
        'pool_recycle': 280,
        'pool_size': 5,
        'max_overflow': 10
    },
    MAIL_SERVER='in-v3.mailjet.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='1fd0031772706f052fe8be9795cb647e',
    MAIL_PASSWORD='76edca49cf2a60c8e1822679ca475a81',
    MAIL_DEFAULT_SENDER=('VDR Admin', 'trilesh.neermul@bramston.co')
)

mail, bcrypt, db = Mail(app), Bcrypt(app), SQLAlchemy(app)
TEMP_FILES = []

# ----------------------------- MODELS ----------------------------- #
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(100), nullable=False)
    lname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

participant_projects = db.Table('participant_projects',
    db.Column('participant_id', db.Integer, db.ForeignKey('participant.id'), primary_key=True),
    db.Column('project_id', db.Integer, db.ForeignKey('project.id'), primary_key=True)
)

class Project(db.Model):
    __tablename__ = 'project'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    participants = db.relationship(
        'Participant',
        secondary=participant_projects,
        back_populates='projects'
    )

class Participant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    group_name = db.Column(db.String(100))
    role = db.Column(db.String(50))
    status = db.Column(db.String(20))
    last_signin = db.Column(db.DateTime)
    project_name = db.Column(db.String(100), nullable=False)
    projects = db.relationship(
    'Project',
    secondary=participant_projects,
    back_populates='participants'
)

class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('documents.id'))
    is_folder = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text)
    labels = db.Column(db.Text)
    filename = db.Column(db.String(255))
    pages = db.Column(db.String(255))
    size_kb = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    project_name = db.Column(db.String(100), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    author_name = db.Column(db.String(100))
    author_email = db.Column(db.String(100))
    group_name = db.Column(db.String(100))
    action = db.Column(db.String(100))
    description = db.Column(db.Text)

# -------------------------- HELPERS ----------------------------- #
def nocache(view):
    @wraps(view)
    def no_cache(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return no_cache

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def generate_password(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*()-_=+", k=length))

def send_login_email(to_email, name, password):
    msg = Message("Your login details",
                  recipients=[to_email],
                  body=f"Hello {name},\n\nYour password: {password}\nPlease login and change it.")
    mail.send(msg)

def get_folder_full_path(folder):
    parts = []
    while folder:
        parts.append(secure_filename(folder.name))
        folder = Document.query.get(folder.parent_id) if folder.parent_id else None
    parts.reverse()
    return os.path.join(app.config['UPLOAD_FOLDER'], *parts)

def get_folder_tree():
    project = session.get('project_name')
    folders = Document.query.filter_by(is_folder=True, project_name=project).all()
    children_map = {}
    for folder in folders:
        children_map.setdefault(folder.parent_id, []).append(folder)

    def build_options(parent_id=None, level=0):
        items = []
        for folder in sorted(children_map.get(parent_id, []), key=lambda x: x.name.lower()):
            items.append((folder.id, f"{'—' * level} {folder.name}"))
            items.extend(build_options(folder.id, level + 1))
        return items

    return build_options()

@atexit.register
def cleanup_temp_files():
    for path in TEMP_FILES:
        try:
            os.remove(path)
        except Exception:
            continue

# ----------------------------- ROUTES ----------------------------- #
@app.route('/')
def index():
    return redirect(url_for('login'))


logging.basicConfig(level=logging.INFO)

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Server Error: {error}", exc_info=True)
    return "Internal Server Error", 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            participant = Participant.query.filter_by(email=email).first()
            if not participant:
                flash("No participant record found for user.", "error")
                return redirect(url_for('login'))

            session['user_id'] = user.id
            session['user_email'] = user.email
            session['fname'] = user.fname
            session['lname'] = user.lname

            projects = participant.projects
            if len(projects) == 1:
                session['project_id'] = projects[0].id
                session['project_name'] = projects[0].name
                return redirect(url_for('participants'))
            elif len(projects) > 1:
                session['temp_participant_id'] = participant.id
                return redirect(url_for('select_project'))
            else:
                flash("You have no projects assigned.", "error")
                return redirect(url_for('login'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')
 except Exception as e:
    app.logger.error(f"Login failed: {e}", exc_info=True)
    return "Login Error", 500
    
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/select-project', methods=['GET', 'POST'])
def select_project():
    participant = Participant.query.get(session.get('temp_participant_id'))
    if not participant:
        return redirect(url_for('login'))

    if request.method == 'POST':
        project_id = int(request.form['project_id'])
        project = Project.query.get(project_id)
        if project not in participant.projects:
            flash("Invalid project selected.", "error")
            return redirect(url_for('select_project'))

        session['project_id'] = project.id
        session['project_name'] = project.name
        session.pop('temp_participant_id', None)
        return redirect(url_for('participants'))

    return render_template('select_project.html', projects=participant.projects)

@app.route('/participants')
@login_required
def participants():
    project_id = session.get('project_id')
    if not project_id:
        return redirect(url_for('select_project'))

    participants = Participant.query.join(Participant.projects).filter(Project.id == project_id).all()
    return render_template('participants.html', users=participants)

@app.route('/documents')
@login_required
def documents():
    project_id = session.get('project_id')
    if not project_id:
        return redirect(url_for('select_project'))

    folder_id = request.args.get('folder_id', type=int)
    if folder_id := request.args.get('folder_id', type=int):
        current_folder = Document.query.filter_by(id=folder_id, project_id=project_id).first_or_404()
        documents = Document.query.filter_by(parent_id=current_folder.id, project_id=project_id).all()
    else:
        current_folder = None
        documents = Document.query.filter_by(parent_id=None, project_id=project_id).all()
    breadcrumb, parent = [], current_folder
    while parent:
        breadcrumb.insert(0, parent)
        parent = Document.query.get(parent.parent_id)
    viewed_ids = session.get('recently_viewed', [])
    recently_viewed_docs = Document.query.filter(Document.id.in_(viewed_ids)).all()
    recently_viewed_docs.sort(key=lambda d: viewed_ids.index(d.id))
    project = session.get('project_name')
    newly_uploaded_docs = Document.query.filter_by(project_name=project).order_by(Document.created_at.desc()).limit(5).all()
    return render_template('documents.html', documents=documents, current_folder=current_folder, breadcrumb=breadcrumb, recently_viewed_docs=recently_viewed_docs, newly_uploaded_docs=newly_uploaded_docs, favorites_docs=[])

@app.route('/upload-document', methods=['GET', 'POST'])
@login_required
def upload_document():
    folders = get_folder_tree()
    if request.method == 'POST':
        project = session.get('project_name')
        projectid = session.get('project_id')
        name = request.form['name']
        parent_id = request.form.get('parent_id') or None
        is_folder = 'is_folder' in request.form
        notes = request.form.get('notes')
        labels = request.form.get('labels')
        if is_folder:
            folder_path = app.config['UPLOAD_FOLDER']
            if parent_id:
                parent = Document.query.get(parent_id)
                folder_path = get_folder_full_path(parent)
            folder_path = os.path.join(folder_path, secure_filename(name))
            os.makedirs(folder_path, exist_ok=True)
            db.session.add(Document(name=name, parent_id=parent_id, is_folder=True, notes=notes, labels=labels, filename=None, pages=0, size_kb=0, created_at=datetime.utcnow(), project_name=project, project_id=projectid))
            db.session.commit()
            flash("Folder created successfully.", "success")
            return redirect(url_for('documents'))
        file = request.files.get('file')
        if not file or file.filename == '':
            flash("No file selected.", "danger")
            return redirect(request.url)
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        pages = len(PdfReader(file_path).pages) if file_path.endswith('.pdf') else 0
        size_kb = round(os.path.getsize(file_path) / 1024, 2)
        db.session.add(Document(name=name, parent_id=parent_id, is_folder=False, notes=notes, labels=labels, filename=filename, pages=pages, size_kb=size_kb, created_at=datetime.utcnow(), project_name=project, project_id=projectid))
        db.session.commit()
        flash("Document uploaded successfully.", "success")
        return redirect(url_for('documents'))
    return render_template('upload_document.html', folders=folders)

@app.route('/view_document/<int:doc_id>')
def view_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    session['recently_viewed'] = [doc_id] + [i for i in session.get('recently_viewed', []) if i != doc_id][:4]
    email = session.get('participant_email') or session.get('user_email')
    viewer = Participant.query.filter_by(email=email).first()
    full_name = viewer.name if viewer else 'Unknown Viewer'
    if viewer:
        db.session.add(ActivityLog(author_name=viewer.name, author_email=viewer.email, group_name=viewer.group_name, action="View Document", description=f"Viewed document '{doc.name}'"))
        db.session.commit()
    temp_path = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf', dir=app.config['UPLOAD_FOLDER']).name
    add_watermark_to_pdf(os.path.join(app.config['UPLOAD_FOLDER'], doc.filename), full_name, temp_path)
    TEMP_FILES.append(temp_path)
    return render_template('view_document.html', document=doc, file_url=url_for('uploaded_file', filename=os.path.basename(temp_path)))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory('uploads', filename)

@app.route('/participants/add', methods=['GET', 'POST'])
@login_required
def add_participant():
    # Guard clause for GET request
    if request.method != 'POST':
        return render_template('add_participant.html')

    name = request.form['name']
    email = request.form['email']
    group_name = request.form['group_name']
    role = request.form['role']
    status = request.form['status']
    send_email = 'send_email' in request.form

    # Guard clause for duplicate email check
    if Participant.query.filter_by(email=email).first() or User.query.filter_by(email=email).first():
        flash('A participant or user with this email already exists.', 'error')
        return redirect(url_for('add_participant'))

    # Generate and hash password
    password = generate_password()
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create user and participant
    user = User(
        fname=name.split()[0],
        lname=' '.join(name.split()[1:]) if len(name.split()) > 1 else '',
        email=email,
        password=hashed_password
    )
    participant = Participant(
        name=name,
        email=email,
        group_name=group_name,
        role=role,
        status=status,
        last_signin=None,
        project_name=session.get('project_name')  # ← ensure folders match current project
    )

    db.session.add_all([user, participant])
    db.session.commit()

    if send_email:
        send_login_email(email, name, password)

    return jsonify({'password': password})

@app.route('/create-user', methods=['GET', 'POST'])
@login_required
def create_user():
    if request.method == 'POST':
        db.session.add(User(email=request.form['email'], password=bcrypt.generate_password_hash(request.form['password']).decode('utf-8')))
        db.session.commit()
        flash('User created.', 'success')
        return redirect(url_for('participants'))
    return render_template('create_user.html')

@app.route('/activity-log')
@login_required
def activity_log():
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
    return render_template('activity_log.html', logs=logs)

@app.route('/my-profile', methods=['GET', 'POST'])
@login_required
def my_profile():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        if not bcrypt.check_password_hash(user.password, request.form['current_password']):
            flash('Incorrect current password.', 'error')
            return redirect(url_for('my_profile'))
        user.fname, user.lname, user.email = request.form['fname'], request.form['lname'], request.form['email']
        if request.form.get('new_password'):
            pw = request.form['new_password']
            if len(pw) < 8 or not any(c.isupper() for c in pw) or not any(c.isdigit() for c in pw):
                flash('Password must be stronger.', 'error')
                return redirect(url_for('my_profile'))
            user.password = bcrypt.generate_password_hash(pw).decode('utf-8')
        db.session.commit()
        session.update(fname=user.fname, lname=user.lname, user_email=user.email)
        flash('Profile updated.', 'success')
        return redirect(url_for('my_profile'))
    return render_template('my_profile.html', user=user)

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)
