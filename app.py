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
from watermark_merger import add_watermark_to_pdf
from flask import render_template, request, redirect, url_for, flash
from sqlalchemy import text
from flask import abort

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

group_project = db.Table('group_projects',
    db.Column('group_name', db.String, db.ForeignKey('participant.group_name')),
    db.Column('project_id', db.Integer, db.ForeignKey('project.id'))
)

participant_projects = db.Table('participant_projects',
    db.Column('participant_id', db.Integer, db.ForeignKey('participant.id'), primary_key=True),
    db.Column('project_id', db.Integer, db.ForeignKey('project.id'), primary_key=True),
    db.Column('can_view', db.Boolean, default=True),
    db.Column('can_upload', db.Boolean, default=False),
    db.Column('can_download', db.Boolean, default=False),
    db.Column('can_edit', db.Boolean, default=False),
    db.Column('can_delete', db.Boolean, default=False)
)

class Project(db.Model):
    __tablename__ = 'project'  # <-- Match this with ForeignKey target below
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

    participant_projects = db.relationship("ParticipantProject", back_populates="project")


class Participant(db.Model):
    __tablename__ = 'participant'  # <-- Explicitly define table name
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    group_name = db.Column(db.String(100))
    role = db.Column(db.String(50))
    status = db.Column(db.String(20))
    last_signin = db.Column(db.DateTime)
    project_name = db.Column(db.String(100), nullable=False)

    participant_projects = db.relationship("ParticipantProject", back_populates="participant")

    # Useful for querying projects directly from a participant
    projects = db.relationship("Project", secondary="participant_projects", viewonly=True, backref="participants")


class ParticipantProject(db.Model):
    __tablename__ = 'participant_projects'
    __table_args__ = {'extend_existing': True}

    participant_id = db.Column(db.Integer, db.ForeignKey('participant.id'), primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), primary_key=True)

    can_view = db.Column(db.Boolean, default=True)
    can_upload = db.Column(db.Boolean, default=False)
    can_download = db.Column(db.Boolean, default=False)
    can_edit = db.Column(db.Boolean, default=False)
    can_delete = db.Column(db.Boolean, default=False)

    participant = db.relationship("Participant", back_populates="participant_projects")
    project = db.relationship("Project", back_populates="participant_projects")



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

@app.route('/login', methods=['GET', 'POST'])
def login():
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
            session['role'] = participant.role.capitalize()
            session['group_name'] = participant.group_name

            projects = participant.projects
            if len(projects) == 1:
                session['project_id'] = projects[0].id
                session['project_name'] = projects[0].name
                session['group_name'] = participant.group_name
                return redirect(url_for('participants'))
            elif len(projects) > 1:
                session['temp_participant_id'] = participant.id
                session['group_name'] = participant.group_name
                return redirect(url_for('select_project'))
            else:
                flash("You have no projects assigned.", "error")
                return redirect(url_for('login'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/select-project', methods=['GET', 'POST'])
@login_required
def select_project():
    group_name = session.get('group_name')

    if not group_name:
        flash("Group not found for the current user.", "danger")
        return redirect(url_for('documents'))

    # Get projects linked to the group
    projects = db.session.query(Project).join(group_project).filter(group_project.c.group_name == group_name).all()

    if request.method == 'POST':
        selected_id = request.form.get('project_id')
        selected = Project.query.get(selected_id)

        if not selected:
            flash("Invalid project selected.", "danger")
            return redirect(request.url)

        session['project_id'] = selected.id
        session['project_name'] = selected.name
        flash(f"Project '{selected.name}' selected successfully.", "success")
        return redirect(url_for('documents'))

    return render_template('select_project.html', projects=projects)


@app.route('/participants')
def participants():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    role = session.get('role')
    group_name = session.get('group_name')
    project_id = session.get('project_id')

    # Admin: See all participants in the current project (or all if project not selected)
    if role == 'Admin' and not group_name:
        if project_id:
            participants = db.session.execute(text("""
                SELECT p.*
                FROM participant p
                JOIN participant_projects pp ON p.id = pp.participant_id
                WHERE pp.project_id = :project_id
            """), {'project_id': project_id}).fetchall()
        else:
            participants = db.session.execute(text("SELECT * FROM participant")).fetchall()

    # Regular users: only see participants from same group and project
    elif group_name and project_id:
        participants = db.session.execute(text("""
            SELECT p.*
            FROM participant p
            JOIN participant_projects pp ON p.id = pp.participant_id
            WHERE p.group_name = :group_name AND pp.project_id = :project_id
        """), {'group_name': group_name, 'project_id': project_id}).fetchall()
    else:
        participants = []

    return render_template('participants.html', participants=participants)


@app.route('/group_project_matrix')
@login_required
def group_project_matrix():
    matrix = db.session.execute(text("""
        SELECT p.name AS user, p.group_name, gp.project_id, pr.name AS project
        FROM participant p
        JOIN group_projects gp ON p.group_name = gp.group_name
        JOIN project pr ON gp.project_id = pr.id
        ORDER BY p.group_name, p.name
    """)).fetchall()
    return render_template("group_project_matrix.html", matrix=matrix)

@app.route('/documents')
@login_required
def documents():
    project_id = session.get('project_id')
    if not project_id:
        return redirect(url_for('select_project'))

    role = session.get('role')
    group_name = session.get('group_name')

    folder_id = request.args.get('folder_id', type=int)

    if role == 'Admin' and not group_name:
        # Admins with no group see all documents for the project
        if folder_id:
            current_folder = Document.query.filter_by(id=folder_id, project_id=project_id).first_or_404()
            documents = Document.query.filter_by(parent_id=current_folder.id, project_id=project_id).all()
        else:
            current_folder = None
            documents = Document.query.filter_by(parent_id=None, project_id=project_id).all()
    else:
        # Regular users can only see documents for the project and folder (if selected)
        if folder_id:
            current_folder = Document.query.filter_by(id=folder_id, project_id=project_id).first_or_404()
            documents = Document.query.filter_by(parent_id=current_folder.id, project_id=project_id).all()
        else:
            current_folder = None
            documents = Document.query.filter_by(parent_id=None, project_id=project_id).all()

    # Breadcrumb logic
    breadcrumb, parent = [], current_folder
    while parent:
        breadcrumb.insert(0, parent)
        parent = Document.query.get(parent.parent_id)

    # Recently viewed
    viewed_ids = session.get('recently_viewed', [])
    recently_viewed_docs = Document.query.filter(Document.id.in_(viewed_ids)).all()
    recently_viewed_docs.sort(key=lambda d: viewed_ids.index(d.id))

    # New uploads (limit 5)
    project_name = session.get('project_name')
    newly_uploaded_docs = Document.query.filter_by(project_name=project_name).order_by(Document.created_at.desc()).limit(5).all()

    return render_template('documents.html',
                           documents=documents,
                           current_folder=current_folder,
                           breadcrumb=breadcrumb,
                           recently_viewed_docs=recently_viewed_docs,
                           newly_uploaded_docs=newly_uploaded_docs,
                           favorites_docs=[])

@app.route('/upload-document', methods=['GET', 'POST'])
@login_required
def upload_document():
    folders = get_folder_tree()
    participant = Participant.query.filter_by(email=session['user_email']).first()
    projects = participant.projects  # for dropdown

    if request.method == 'POST':
        name = request.form['name']
        parent_id = request.form.get('parent_id') or None
        is_folder = 'is_folder' in request.form
        project_id = request.form.get('project_id')

        # Ensure project is selected
        if not project_id:
            flash("Please select a project.", "danger")
            return redirect(request.url)

        # Get the selected project's name
        selected_project = Project.query.get(project_id)
        if not selected_project:
            flash("Invalid project selected.", "danger")
            return redirect(request.url)

        project_name = selected_project.name
        notes = request.form.get('notes')
        labels = request.form.get('labels')

        if is_folder:
            folder_path = app.config['UPLOAD_FOLDER']
            if parent_id:
                parent = Document.query.get(parent_id)
                folder_path = get_folder_full_path(parent)
            folder_path = os.path.join(folder_path, secure_filename(name))
            os.makedirs(folder_path, exist_ok=True)

            db.session.add(Document(
                name=name,
                parent_id=parent_id,
                is_folder=True,
                notes=notes,
                labels=labels,
                filename=None,
                pages=0,
                size_kb=0,
                created_at=datetime.utcnow(),
                project_name=project_name,
                project_id=project_id
            ))
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

        db.session.add(Document(
            name=name,
            parent_id=parent_id,
            is_folder=False,
            notes=notes,
            labels=labels,
            filename=filename,
            pages=pages,
            size_kb=size_kb,
            created_at=datetime.utcnow(),
            project_name=project_name,
            project_id=project_id
        ))
        db.session.commit()
        flash("Document uploaded successfully.", "success")
        return redirect(url_for('documents'))

    return render_template('upload_document.html', folders=folders, projects=projects)

@app.route('/view_document/<int:doc_id>')
def view_document(doc_id):
    # Fetch document
    doc = Document.query.get_or_404(doc_id)

    # Track recent documents in session
    session['recently_viewed'] = [doc_id] + [
        i for i in session.get('recently_viewed', []) if i != doc_id
    ][:4]

    # Determine viewer (admin or participant)
    email = session.get('participant_email') or session.get('user_email')
    viewer = Participant.query.filter_by(email=email).first()
    full_name = viewer.name if viewer else 'Unknown Viewer'

    # Log the view activity
    if viewer:
        log = ActivityLog(
            author_name=viewer.name,
            author_email=viewer.email,
            group_name=viewer.group_name,
            action="View Document",
            description=f"Viewed document '{doc.name}'"
        )
        db.session.add(log)
        db.session.commit()

    # Determine if user has download permission
    can_download = False
    if viewer:
        if viewer.role == 'Admin':
            can_download = True
        else:
            permission = ParticipantProject.query.filter_by(
                participant_id=viewer.id,
                project_id=doc.project_id
            ).first()
            if permission and permission.can_download:
                can_download = True

    # Generate watermarked file
    temp_path = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf', dir=app.config['UPLOAD_FOLDER']).name
    add_watermark_to_pdf(
        os.path.join(app.config['UPLOAD_FOLDER'], doc.filename),
        full_name,
        temp_path
    )
    TEMP_FILES.append(temp_path)

    return render_template(
        'view_document.html',
        document=doc,
        file_url=url_for('uploaded_file', filename=os.path.basename(temp_path)),
        can_download=can_download
    )
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

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

@app.route('/activity_log')
def activity_log():
    role = session.get('role')
    user_group = session.get('group_name')

    if role == 'Admin' and not user_group:
        # Admin with no group: see all logs
        logs = db.session.execute(text("""
            SELECT al.* FROM activity_log al
            ORDER BY al.timestamp DESC
        """)).fetchall()
    else:
        # Non-admins: only see logs from their group
        logs = db.session.execute(text("""
            SELECT al.* FROM activity_log al
            JOIN participant p ON al.author_email = p.email
            WHERE p.group_name = :group
            ORDER BY al.timestamp DESC
        """), {'group': user_group}).fetchall()

    return render_template("activity_log.html", logs=logs)

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


@app.route('/manage-permissions/<int:participant_id>', methods=['GET', 'POST'])
@login_required
def manage_permissions(participant_id):
    if session.get('role') != 'Admin':
        abort(403)

    participant = Participant.query.get_or_404(participant_id)
    projects = participant.projects

    if request.method == 'POST':
        for project in projects:
            can_view = request.form.get(f'view_{project.id}') == 'on'
            can_upload = request.form.get(f'upload_{project.id}') == 'on'
            can_download = request.form.get(f'download_{project.id}') == 'on'
            can_edit = request.form.get(f'edit_{project.id}') == 'on'
            can_delete = request.form.get(f'delete_{project.id}') == 'on'

            db.session.execute(text("""
                UPDATE participant_projects
                SET can_view = :v, can_upload = :u, can_download = :d, can_edit = :e, can_delete = :del
                WHERE participant_id = :pid AND project_id = :projid
            """), {
                'v': can_view, 'u': can_upload, 'd': can_download,
                'e': can_edit, 'del': can_delete,
                'pid': participant.id, 'projid': project.id
            })
        db.session.commit()
        flash("Permissions updated.", "success")
        return redirect(url_for('participants'))

    # render template with checkboxes per project
    return render_template("manage_permissions.html", participant=participant, projects=projects)

@app.route('/assign_group_project', methods=['GET', 'POST'])
@login_required
def assign_group_project():
    if session.get('role') != 'Admin':
        return redirect(url_for('index'))

    if request.method == 'POST':
        group_name = request.form['group_name']
        project_id = request.form['project_id']
        db.session.execute(
            text("INSERT INTO group_projects (group_name, project_id) VALUES (:group_name, :project_id)"),
            {"group_name": group_name, "project_id": project_id}
        )
        db.session.commit()
        flash("Group assigned to project successfully.")
        return redirect(url_for('assign_group_project'))

    groups = db.session.execute(text("SELECT DISTINCT group_name FROM participant")).fetchall()
    projects = db.session.execute(text("SELECT id, name FROM project")).fetchall()
    return render_template("assign_group_project.html", groups=groups, projects=projects)

@app.route('/create-project', methods=['GET', 'POST'])
@login_required
def create_project():
    if session.get('role') != 'Admin':
        flash("Access denied.", "danger")
        return redirect(url_for('participants'))

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')

        if not name:
            flash("Project name is required.", "danger")
            return redirect(url_for('create_project'))

        # Check for existing project
        if Project.query.filter_by(name=name).first():
            flash("Project with this name already exists.", "warning")
            return redirect(url_for('create_project'))

        new_project = Project(name=name, description=description)
        db.session.add(new_project)
        db.session.commit()
        flash("Project created successfully.", "success")
        return redirect(url_for('participants'))  # Or a project list page

    return render_template('create_project.html')

@app.route('/assign_permissions', methods=['GET', 'POST'])
def assign_permissions():
    participants = Participant.query.all()
    projects = Project.query.all()
    permissions = ParticipantProject.query.all()

    selected_entry = None

    if request.method == 'GET' and request.args.get('participant_id') and request.args.get('project_id'):
        selected_entry = ParticipantProject.query.get((
            request.args.get('participant_id'),
            request.args.get('project_id')
        ))

    if request.method == 'POST':
        participant_id = int(request.form['participant_id'])
        project_id = int(request.form['project_id'])

        # Get or create entry
        entry = ParticipantProject.query.get((participant_id, project_id))
        if not entry:
            entry = ParticipantProject(participant_id=participant_id, project_id=project_id)
            db.session.add(entry)

        entry.can_edit = 'can_edit' in request.form
        entry.can_download = 'can_download' in request.form
        entry.can_upload = 'can_upload' in request.form
        entry.can_delete = 'can_delete' in request.form

        db.session.commit()
        return redirect(url_for('assign_permissions'))

    return render_template(
        "assign_permissions.html",
        participants=participants,
        projects=projects,
        permissions=permissions,
        selected_entry=selected_entry
    )

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)