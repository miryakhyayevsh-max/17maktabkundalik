import os
from datetime import datetime, date
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-before-production")
db_url = os.environ.get("DATABASE_URL", "sqlite:///kundalik.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

ADMIN_ROLES = {"Главный администратор", "Заместитель директора", "Директор"}
ALL_ROLES = ["Главный администратор", "Заместитель директора", "Директор",
             "Учитель", "Классный руководитель", "Ученик", "Родитель", "Психолог"]

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(160), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(60), nullable=False, default="Ученик")
    must_change_password = db.Column(db.Boolean, default=True)
    active = db.Column(db.Boolean, default=True)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    @property
    def is_admin(self):
        return self.role in ADMIN_ROLES

class SchoolClass(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True, nullable=False)

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey("subject.id"), nullable=False)
    value = db.Column(db.Integer, nullable=False)
    kind = db.Column(db.String(30), default="Оценка")
    note = db.Column(db.String(250), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    student = db.relationship("User")
    subject = db.relationship("Subject")

class Homework(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_name = db.Column(db.String(30), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey("subject.id"), nullable=False)
    description = db.Column(db.Text, nullable=False)
    due_date = db.Column(db.Date, nullable=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    subject = db.relationship("Subject")
    teacher = db.relationship("User")

class Lesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_name = db.Column(db.String(30), nullable=False)
    weekday = db.Column(db.String(20), nullable=False)
    lesson_number = db.Column(db.Integer, nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey("subject.id"), nullable=False)
    room = db.Column(db.String(30), default="")
    subject = db.relationship("Subject")

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    lesson_date = db.Column(db.Date, nullable=False, default=date.today)
    status = db.Column(db.String(2), nullable=False)
    note = db.Column(db.String(200), default="")
    student = db.relationship("User")

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    author = db.relationship("User")

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapped

@app.context_processor
def inject_globals():
    return {"admin_roles": ADMIN_ROLES, "all_roles": ALL_ROLES}

@app.route("/")
@login_required
def index():
    counts = {
        "users": User.query.count(), "classes": SchoolClass.query.count(),
        "subjects": Subject.query.count(), "grades": Grade.query.count()
    }
    if current_user.is_admin:
        recent_grades = Grade.query.order_by(Grade.created_at.desc()).limit(8).all()
        homework = Homework.query.order_by(Homework.id.desc()).limit(6).all()
    elif current_user.role in ("Ученик", "Родитель"):
        recent_grades = Grade.query.filter_by(student_id=current_user.id).order_by(Grade.created_at.desc()).limit(8).all()
        homework = Homework.query.order_by(Homework.id.desc()).limit(6).all()
    else:
        recent_grades = Grade.query.order_by(Grade.created_at.desc()).limit(8).all()
        homework = Homework.query.order_by(Homework.id.desc()).limit(6).all()
    announcements = Announcement.query.order_by(Announcement.created_at.desc()).limit(5).all()
    return render_template("index.html", counts=counts, grades=recent_grades, homework=homework, announcements=announcements)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form.get("username", "").strip()).first()
        if user and user.active and user.check_password(request.form.get("password", "")):
            login_user(user)
            if user.must_change_password:
                return redirect(url_for("change_password"))
            return redirect(url_for("index"))
        flash("Неверный логин или пароль.", "error")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        p1, p2 = request.form.get("password", ""), request.form.get("password2", "")
        if len(p1) < 10:
            flash("Новый пароль должен содержать минимум 10 символов.", "error")
        elif p1 != p2:
            flash("Пароли не совпадают.", "error")
        else:
            current_user.set_password(p1)
            current_user.must_change_password = False
            db.session.commit()
            flash("Пароль изменён.", "success")
            return redirect(url_for("index"))
    return render_template("change_password.html")

@app.route("/users", methods=["GET", "POST"])
@admin_required
def users():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "Ученик")
        if not username or not full_name or len(password) < 10 or role not in ALL_ROLES:
            flash("Заполните поля. Временный пароль — минимум 10 символов.", "error")
        elif User.query.filter_by(username=username).first():
            flash("Такой логин уже существует.", "error")
        else:
            u = User(username=username, full_name=full_name, role=role)
            u.set_password(password)
            db.session.add(u); db.session.commit()
            flash("Пользователь создан. При первом входе он должен сменить пароль.", "success")
            return redirect(url_for("users"))
    return render_template("users.html", users=User.query.order_by(User.full_name).all())

@app.route("/classes", methods=["GET", "POST"])
@admin_required
def classes():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if name and not SchoolClass.query.filter_by(name=name).first():
            db.session.add(SchoolClass(name=name)); db.session.commit()
            flash("Класс добавлен.", "success")
        else:
            flash("Введите уникальное название класса.", "error")
        return redirect(url_for("classes"))
    return render_template("classes.html", classes=SchoolClass.query.order_by(SchoolClass.name).all())

@app.route("/subjects", methods=["GET", "POST"])
@admin_required
def subjects():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if name:
            db.session.add(Subject(name=name)); db.session.commit()
            flash("Предмет добавлен.", "success")
        return redirect(url_for("subjects"))
    return render_template("subjects.html", subjects=Subject.query.order_by(Subject.name).all())

@app.route("/grades", methods=["GET", "POST"])
@login_required
def grades():
    students = User.query.filter_by(role="Ученик", active=True).order_by(User.full_name).all()
    subjects = Subject.query.order_by(Subject.name).all()
    if request.method == "POST":
        if not (current_user.is_admin or current_user.role in ("Учитель", "Классный руководитель")):
            abort(403)
        try:
            value = int(request.form.get("value", "0"))
            student_id = int(request.form.get("student_id", "0"))
            subject_id = int(request.form.get("subject_id", "0"))
        except ValueError:
            abort(400)
        if value < 1 or value > 10 or not db.session.get(User, student_id) or not db.session.get(Subject, subject_id):
            flash("Проверьте ученика, предмет и оценку от 1 до 10.", "error")
        else:
            db.session.add(Grade(student_id=student_id, subject_id=subject_id, value=value,
                                 kind=request.form.get("kind", "Оценка"), note=request.form.get("note", "")))
            db.session.commit()
            flash("Оценка сохранена.", "success")
        return redirect(url_for("grades"))
    if current_user.role in ("Ученик", "Родитель"):
        items = Grade.query.filter_by(student_id=current_user.id).order_by(Grade.created_at.desc()).all()
    else:
        items = Grade.query.order_by(Grade.created_at.desc()).limit(100).all()
    can_add = current_user.is_admin or current_user.role in ("Учитель", "Классный руководитель")
    return render_template("grades.html", grades=items, students=students, subjects=subjects, can_add=can_add)

@app.route("/homework", methods=["GET", "POST"])
@login_required
def homework():
    subjects = Subject.query.order_by(Subject.name).all()
    if request.method == "POST":
        if not (current_user.is_admin or current_user.role in ("Учитель", "Классный руководитель")):
            abort(403)
        try:
            subject_id = int(request.form.get("subject_id", "0"))
        except ValueError:
            abort(400)
        desc = request.form.get("description", "").strip()
        cls = request.form.get("class_name", "").strip()
        if not desc or not cls or not db.session.get(Subject, subject_id):
            flash("Заполните все поля.", "error")
        else:
            due = request.form.get("due_date")
            db.session.add(Homework(class_name=cls, subject_id=subject_id, description=desc,
                                    due_date=date.fromisoformat(due) if due else None, teacher_id=current_user.id))
            db.session.commit()
            flash("Домашнее задание опубликовано.", "success")
        return redirect(url_for("homework"))
    items = Homework.query.order_by(Homework.id.desc()).all()
    can_add = current_user.is_admin or current_user.role in ("Учитель", "Классный руководитель")
    return render_template("homework.html", homework=items, subjects=subjects, can_add=can_add)

@app.route("/schedule", methods=["GET", "POST"])
@login_required
def schedule():
    subjects = Subject.query.order_by(Subject.name).all()
    if request.method == "POST":
        if not current_user.is_admin: abort(403)
        try:
            num, sid = int(request.form.get("lesson_number", "0")), int(request.form.get("subject_id", "0"))
        except ValueError: abort(400)
        if 1 <= num <= 10 and db.session.get(Subject, sid):
            db.session.add(Lesson(class_name=request.form.get("class_name","").strip(),
                                  weekday=request.form.get("weekday","Понедельник"),
                                  lesson_number=num, subject_id=sid, room=request.form.get("room","").strip()))
            db.session.commit(); flash("Урок добавлен.", "success")
        return redirect(url_for("schedule"))
    return render_template("schedule.html", lessons=Lesson.query.order_by(Lesson.weekday, Lesson.lesson_number).all(), subjects=subjects)

@app.route("/attendance", methods=["GET", "POST"])
@login_required
def attendance():
    students = User.query.filter_by(role="Ученик", active=True).order_by(User.full_name).all()
    if request.method == "POST":
        if not (current_user.is_admin or current_user.role in ("Учитель", "Классный руководитель")): abort(403)
        try: sid = int(request.form.get("student_id", "0"))
        except ValueError: abort(400)
        status = request.form.get("status", "")
        if status not in ("Н", "О", "Б", "П") or not db.session.get(User, sid):
            flash("Проверьте данные посещаемости.", "error")
        else:
            d = request.form.get("lesson_date")
            db.session.add(Attendance(student_id=sid, lesson_date=date.fromisoformat(d) if d else date.today(),
                                      status=status, note=request.form.get("note","")))
            db.session.commit(); flash("Посещаемость сохранена.", "success")
        return redirect(url_for("attendance"))
    items = Attendance.query.order_by(Attendance.lesson_date.desc()).limit(100).all()
    return render_template("attendance.html", students=students, items=items,
                           can_add=current_user.is_admin or current_user.role in ("Учитель","Классный руководитель"))

@app.route("/announcements", methods=["GET", "POST"])
@login_required
def announcements():
    if request.method == "POST":
        if not current_user.is_admin: abort(403)
        title, body = request.form.get("title","").strip(), request.form.get("body","").strip()
        if title and body:
            db.session.add(Announcement(title=title, body=body, author_id=current_user.id))
            db.session.commit(); flash("Объявление опубликовано.", "success")
        return redirect(url_for("announcements"))
    return render_template("announcements.html", announcements=Announcement.query.order_by(Announcement.created_at.desc()).all())

@app.errorhandler(403)
def forbidden(_):
    return render_template("message.html", title="Нет доступа", message="У вашей учётной записи нет прав для этого раздела."), 403

@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("Database tables created.")

@app.cli.command("create-admin")
def create_admin():
    db.create_all()
    username = os.environ.get("ADMIN_USERNAME")
    password = os.environ.get("ADMIN_PASSWORD")
    if not username or not password or len(password) < 10:
        raise SystemExit("Set ADMIN_USERNAME and ADMIN_PASSWORD (at least 10 characters) first.")
    if User.query.filter_by(username=username).first():
        print("Admin already exists."); return
    user = User(username=username, full_name=os.environ.get("ADMIN_FULL_NAME", "Администратор"),
                role="Главный администратор", must_change_password=True)
    user.set_password(password)
    db.session.add(user); db.session.commit()
    print("Admin created. Change the password at first login.")

with app.app_context():
    db.create_all()

    admin_username = os.environ.get("ADMIN_USERNAME")
    admin_password = os.environ.get("ADMIN_PASSWORD")

    if admin_username and admin_password and len(admin_password) >= 10:
        if not User.query.filter_by(username=admin_username).first():
            admin = User(
                username=admin_username,
                full_name=os.environ.get("ADMIN_FULL_NAME", "Главный администратор"),
                role="Главный администратор",
                must_change_password=True
            )
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
