from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime

# Créez l'application Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'votre_cle_secrete'  # Changez cette clé pour plus de sécurité
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pannes.db'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static', 'uploads')
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Assurez-vous que le dossier d'uploads existe
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Définition du modèle utilisateur (User) avec Flask-Login
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Définition du modèle pour enregistrer les pannes
class Panne(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_panne = db.Column(db.Date, nullable=False)
    conducteur = db.Column(db.String(150), nullable=False)
    engin_type = db.Column(db.String(50), nullable=False)
    engin_type_custom = db.Column(db.String(100), nullable=True)
    engin_num = db.Column(db.String(50), nullable=False)
    geolocalisation = db.Column(db.String(100), nullable=True)
    lieu_text = db.Column(db.String(200), nullable=True)
    description = db.Column(db.String(200), nullable=False)
    photo1 = db.Column(db.String(200), nullable=True)
    photo2 = db.Column(db.String(200), nullable=True)
    photo3 = db.Column(db.String(200), nullable=True)
    impact_reg = db.Column(db.Boolean, default=False)
    temps_perdu = db.Column(db.String(50), nullable=True)
    demande_secours = db.Column(db.Boolean, default=False)
    # Le status peut être 'repaired' (réparée), 'not taken' (non prise en compte) ou 'pending' (en attente)
    status = db.Column(db.String(50), default="pending")
    archived = db.Column(db.Boolean, default=False)

# Fonction de chargement de l'utilisateur pour Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash("Identifiants invalides")
    return render_template('login.html')


# Route de déconnexion
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Page principale : formulaire de saisie de panne
@app.route('/', methods=['GET','POST'])
@login_required
def index():
    if request.method == 'POST':
        # Récupérer et traiter la date
        try:
            date_str = request.form.get('date_panne')
            date_panne = datetime.strptime(date_str, '%Y-%m-%d').date()
        except Exception as e:
            flash("La date n'est pas valide.")
            return redirect(url_for('index'))
        
        conducteur = request.form.get('conducteur')
        engin_type = request.form.get('engin_type')
        engin_type_custom = request.form.get('engin_type_custom') if engin_type == 'Autres' else None
        engin_num = request.form.get('engin_num')
        geolocalisation = request.form.get('geolocalisation')
        lieu_text = request.form.get('lieu_text')
        description = request.form.get('description')
        impact_reg = True if request.form.get('impact_reg') == 'oui' else False
        temps_perdu = request.form.get('temps_perdu') if impact_reg else None
        demande_secours = True if request.form.get('demande_secours') == 'oui' else False
        
        # Fonction pour enregistrer les photos
        def save_photo(field_name):
            file = request.files.get(field_name)
            if file and file.filename:
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                return filename
            return None
        
        photo1 = save_photo('photo1')
        photo2 = save_photo('photo2')
        photo3 = save_photo('photo3')

        panne = Panne(
            date_panne=date_panne,
            conducteur=conducteur,
            engin_type=engin_type,
            engin_type_custom=engin_type_custom,
            engin_num=engin_num,
            geolocalisation=geolocalisation,
            lieu_text=lieu_text,
            description=description,
            photo1=photo1,
            photo2=photo2,
            photo3=photo3,
            impact_reg=impact_reg,
            temps_perdu=temps_perdu,
            demande_secours=demande_secours
        )
        db.session.add(panne)
        db.session.commit()
        flash("Panne enregistrée avec succès!")
        return redirect(url_for('index'))
        
    return render_template('index.html')

# Page de consultation des pannes
@app.route('/records')
@login_required
def records():
    pannes = Panne.query.order_by(Panne.engin_num).all()
    return render_template('records.html', pannes=pannes)

if __name__ == '__main__':
    app.run(debug=True)
