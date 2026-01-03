#!/usr/bin/env python3
"""
Password Manager Web - Interface Web Complète avec Authentification à Double Facteur (2FA)
"""

import os
import sys
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_file
from flask_session import Session
import sqlite3
import hashlib
import json
import base64
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import requests
import random
import string
import io
import smtplib
import ssl
from email.message import EmailMessage

#  CONFIGURATION 

# Obtient le chemin absolu du dossier actuel
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')
DATA_DIR = os.path.join(BASE_DIR, 'data')

# Créer les dossiers si nécessaire
os.makedirs(TEMPLATE_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# Chemin de la base de données
DB_PATH = os.path.join(DATA_DIR, 'passwords.db')

# --- Configuration SMTP pour l'envoi d'emails (À CONFIGURER PAR L'UTILISATEUR) ---
# NOTE: Remplacez ces valeurs par les vôtres. Pour Gmail, vous aurez besoin d'un mot de passe d'application.
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
SENDER_EMAIL = 'naouareya12@gmail.com' # L'email qui envoie le code
MAIL_PASSWORD = 'drgkrufhhvpnltud' # Le mot de passe d'application ou mot de passe SMTP

# FONCTIONS UTILITAIRES 

def send_email_2fa(recipient_email, code):
    """Envoie le code 2FA à l'adresse email du destinataire."""

    if SENDER_EMAIL == 'votre_email_expediteur@gmail.com':
        print(f"ATTENTION: Configuration SMTP non complétée. Code 2FA simulé: {code} pour {recipient_email}")
        return True # Simuler le succès si non configuré 

    msg = EmailMessage()
    msg['Subject'] = 'Votre code de vérification en deux étapes'
    msg['From'] = SENDER_EMAIL
    msg['To'] = recipient_email
    
    body = f"""
Bonjour,

Votre code de vérification en deux étapes est :

{code}

Ce code est valide pour 5 minutes.

Si vous n'avez pas tenté de vous connecter, veuillez ignorer cet email.
"""
    msg.set_content(body)

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
            server.starttls(context=context)
            server.login(SENDER_EMAIL, MAIL_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'email à {recipient_email}: {e}")
        return False

# ==================== CLASSES ====================

class PasswordManager:
    def __init__(self):
        self.init_db()
    
    def init_db(self):
        """Initialise la base de données SQLite."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Table des utilisateurs (avec colonnes 2FA)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                master_key BLOB NOT NULL,
                salt BLOB NOT NULL,
                two_factor_code TEXT,
                two_factor_expiry TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Table des mots de passe
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                url TEXT,
                category TEXT DEFAULT 'Autre',
                notes TEXT,
                breach_count INTEGER DEFAULT 0,
                strength_score INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Table des sessions (ajoutée par app2.py)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def create_user(self, username, master_password):
        """Crée un nouvel utilisateur."""
        # Générer un sel unique
        salt = os.urandom(16)
        
        # Dériver la clé maîtresse avec PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        master_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        
        # Sauvegarder dans la base de données
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                'INSERT INTO users (username, master_key, salt) VALUES (?, ?, ?)',
                (username, master_key, salt)
            )
            user_id = cursor.lastrowid
            conn.commit()
            
            # Créer un répertoire utilisateur pour les clés (logique de app2.py)
            user_dir = os.path.join(DATA_DIR, f"user_{user_id}")
            os.makedirs(user_dir, exist_ok=True)
            
            return user_id
        except sqlite3.IntegrityError:
            return None
        finally:
            conn.close()
    
    def authenticate_user(self, username, master_password):
        """Authentifie un utilisateur."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT id, master_key, salt FROM users WHERE username = ?',
            (username,)
        )
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return None
        
        user_id, stored_key, salt = user
        
        # Dériver la clé depuis le mot de passe fourni
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        test_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        
        if test_key == stored_key:
            return user_id
        return None

    def generate_2fa_code(self, user_id):
        """Génère un code 2FA et le stocke avec une expiration de 5 minutes."""
        code = ''.join(random.choices(string.digits, k=6))
        expiry = (datetime.now() + timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET two_factor_code = ?, two_factor_expiry = ? WHERE id = ?',
            (code, expiry, user_id)
        )
        conn.commit()
        conn.close()
        return code

    def verify_2fa_code(self, user_id, code):
        """Vérifie le code 2FA et l'expiration."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT two_factor_code, two_factor_expiry, username FROM users WHERE id = ?',
            (user_id,)
        )
        result = cursor.fetchone()
        conn.close()

        if not result:
            return False, None

        stored_code, expiry_str, username = result
        
        if stored_code is None or expiry_str is None:
            return False, username # Pas de code en attente

        expiry_time = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S')

        if datetime.now() > expiry_time:
            return False, username # Code expiré

        if code == stored_code:
            # Effacer le code après vérification réussie
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE users SET two_factor_code = NULL, two_factor_expiry = NULL WHERE id = ?',
                (user_id,)
            )
            conn.commit()
            conn.close()
            return True, username
        
        return False, username
    
    def get_cipher(self, user_id, master_password):
        """Retourne un objet Fernet pour le chiffrement."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT salt FROM users WHERE id = ?',
            (user_id,)
        )
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            raise ValueError("Utilisateur non trouvé")
        
        salt = result[0]
        
        # Dériver la clé
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        
        return Fernet(key)
    
    def add_password(self, user_id, master_password, service, username, password, 
                     url='', category='Autre', notes=''):
        """Ajoute un mot de passe chiffré."""
        cipher = self.get_cipher(user_id, master_password)
        encrypted_password = cipher.encrypt(password.encode())
        
        # Vérifier les fuites
        breach_count = self.check_breaches(password)
        
        # Calculer la force
        strength_score = self.calculate_strength(password)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO passwords 
            (user_id, service, username, encrypted_password, url, category, notes, breach_count, strength_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, service, username, encrypted_password, url, category, notes, breach_count, strength_score))
        
        conn.commit()
        conn.close()
        
        return cursor.lastrowid

    def get_password_by_id(self, user_id, master_password, password_id):
        """Récupère un mot de passe spécifique par son ID."""
        cipher = self.get_cipher(user_id, master_password)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, service, username, encrypted_password, url, category, notes,
                   breach_count, strength_score, created_at, updated_at
            FROM passwords
            WHERE id = ? AND user_id = ?
        ''', (password_id, user_id))

        row = cursor.fetchone()
        conn.close()

        if row:
            try:
                decrypted_password = cipher.decrypt(row[3]).decode()
                return {
                    'id': row[0],
                    'service': row[1],
                    'username': row[2],
                    'password': decrypted_password,
                    'url': row[4],
                    'category': row[5],
                    'notes': row[6],
                    'breach_count': row[7],
                    'strength_score': row[8],
                    'created_at': row[9],
                    'updated_at': row[10]
                }
            except Exception as e:
                print(f"⚠  Erreur de déchiffrement: {e}")
                return None
        return None

    def update_password(self, user_id, master_password, password_id, service, username, password,
                       url='', category='Autre', notes=''):
        """Met à jour un mot de passe existant."""
        cipher = self.get_cipher(user_id, master_password)
        encrypted_password = cipher.encrypt(password.encode())

        # Vérifier les fuites
        breach_count = self.check_breaches(password)

        # Calculer la force
        strength_score = self.calculate_strength(password)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE passwords
            SET service = ?, username = ?, encrypted_password = ?, url = ?,
                category = ?, notes = ?, breach_count = ?, strength_score = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
        ''', (service, username, encrypted_password, url, category, notes,
              breach_count, strength_score, password_id, user_id))

        conn.commit()
        affected = cursor.rowcount
        conn.close()

        return affected > 0

    def delete_password(self, user_id, password_id):
        """Supprime un mot de passe."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute(
            'DELETE FROM passwords WHERE id = ? AND user_id = ?',
            (password_id, user_id)
        )

        conn.commit()
        affected = cursor.rowcount
        conn.close()

        return affected > 0

    
    def get_passwords(self, user_id, master_password):
        """Récupère tous les mots de passe déchiffrés."""
        cipher = self.get_cipher(user_id, master_password)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, service, username, encrypted_password, url, category, notes, 
                   breach_count, strength_score, created_at, updated_at
            FROM passwords 
            WHERE user_id = ?
            ORDER BY service
        ''', (user_id,))
        
        passwords = []
        for row in cursor.fetchall():
            try:
                decrypted_password = cipher.decrypt(row[3]).decode()
                passwords.append({
                    'id': row[0],
                    'service': row[1],
                    'username': row[2],
                    'password': decrypted_password,
                    'url': row[4],
                    'category': row[5],
                    'notes': row[6],
                    'breach_count': row[7],
                    'strength_score': row[8],
                    'created_at': row[9],
                    'updated_at': row[10]
                })
            except Exception as e:
                print(f"⚠  Erreur de déchiffrement: {e}")
                continue
        
        conn.close()
        return passwords
    
    def check_breaches(self, password):
        """Vérifie si le mot de passe est dans des fuites."""
        try:
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            
            response = requests.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                headers={'User-Agent': 'PasswordManager-Web'},
                timeout=5
            )
            
            if response.status_code == 200:
                suffix = sha1_hash[5:]
                for line in response.text.splitlines():
                    if line.startswith(suffix):
                        return int(line.split(':')[1])
            return 0
        except Exception as e:
            print(f"⚠  Erreur vérification API: {e}")
            return 0
    
    def calculate_strength(self, password):
        """Calcule un score de force (0-100)."""
        score = 0
        
        # Longueur
        if len(password) >= 8:
            score += 20
        if len(password) >= 12:
            score += 10
        if len(password) >= 16:
            score += 10
        
        # Diversité des caractères
        if any(c.islower() for c in password):
            score += 10
        if any(c.isupper() for c in password):
            score += 10
        if any(c.isdigit() for c in password):
            score += 10
        if any(c in "!@#$%^&*()_-+=[]{}|;:,.<>?" for c in password):
            score += 10
        
        # Pas de motifs simples
        motifs = ["123", "abc", "password", "admin", "qwerty", "azerty"]
        if not any(motif in password.lower() for motif in motifs):
            score += 20
        
        return min(score, 100)
    
    def generate_password(self, length=16, use_lower=True, use_upper=True, 
                         use_digits=True, use_symbols=True):
        """Génère un mot de passe aléatoire."""
        chars = ''
        if use_lower:
            chars += string.ascii_lowercase
        if use_upper:
            chars += string.ascii_uppercase
        if use_digits:
            chars += string.digits
        if use_symbols:
            chars += "!@#$%^&*()_-+=[]{}|;:,.<>?"
        
        if not chars:
            chars = string.ascii_letters + string.digits
        
        # Garantir au moins un de chaque type sélectionné
        password = []
        if use_lower:
            password.append(random.choice(string.ascii_lowercase))
        if use_upper:
            password.append(random.choice(string.ascii_uppercase))
        if use_digits:
            password.append(random.choice(string.digits))
        if use_symbols:
            password.append(random.choice("!@#$%^&*()_-+=[]{}|;:,.<>?"))
        
        # Compléter
        while len(password) < length:
            password.append(random.choice(chars))
        
        random.shuffle(password)
        return ''.join(password)

#  CONFIGURATION FLASK 

# Configuration de l'application Flask
app = Flask(__name__, 
            template_folder=TEMPLATE_DIR,
            static_folder=STATIC_DIR)

app.secret_key = 'password-manager-secret-key-2024'  # À changer en production
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 heure

# Initialiser la session
Session(app)

#  ROUTES FLASK 

@app.route('/')
def index():
    """Page d'accueil."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Page de connexion avec 2FA."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        manager = PasswordManager()
        user_id = manager.authenticate_user(username, password)
        
        if user_id:
            # --- Logique 2FA ---
            # 1. Générer le code 2FA et le stocker en DB
            code_2fa = manager.generate_2fa_code(user_id)
            
            # 2. Envoyer le code par email (username est considéré comme l'email)
            if send_email_2fa(username, code_2fa):
                # 3. Stocker les infos en session temporaire et rediriger vers la vérification 2FA
                session['user_id_pending'] = user_id
                session['username_pending'] = username
                session['master_password_pending'] = password # Stocker temporairement le MP maître
                flash('Un code de vérification a été envoyé à votre adresse email.', 'info')
                return redirect(url_for('verify_2fa'))
            else:
                flash('Erreur lors de l\'envoi du code 2FA. Veuillez réessayer.', 'danger')
                return redirect(url_for('login'))
            # --- Fin de la logique 2FA ---
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect.', 'danger')
    
    return render_template('login.html')

@app.route('/2fa-verify', methods=['GET', 'POST'])
def verify_2fa():
    """Page de vérification du code 2FA."""
    # Si l'utilisateur est déjà complètement connecté, rediriger vers le dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    # Si aucune connexion n'est en attente, rediriger vers la page de login
    if 'user_id_pending' not in session:
        flash('Veuillez vous connecter d\'abord.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('code')
        user_id = session['user_id_pending']
        
        manager = PasswordManager()
        is_valid, username = manager.verify_2fa_code(user_id, code)
        
        if is_valid:
            # Authentification complète réussie
            session['user_id'] = user_id
            session['username'] = username
            session['master_password'] = session['master_password_pending']
            
            # Nettoyer les sessions temporaires
            session.pop('user_id_pending', None)
            session.pop('username_pending', None)
            session.pop('master_password_pending', None)
            
            flash('Vérification réussie. Bienvenue !', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Code de vérification incorrect ou expiré.', 'danger')
            # Ne pas effacer les sessions pending pour permettre une nouvelle tentative
            
    return render_template('2fa_verify.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Page d'inscription."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not password:
            flash('Tous les champs sont requis.', 'danger')
        elif password != confirm_password:
            flash('Les mots de passe ne correspondent pas.', 'danger')
        elif len(password) < 8:
            flash('Le mot de passe doit faire au moins 8 caractères.', 'danger')
        else:
            manager = PasswordManager()
            user_id = manager.create_user(username, password)
            
            if user_id:
                flash('Compte créé avec succès ! Connectez-vous.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Ce nom d\'utilisateur existe déjà.', 'danger')
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    """Tableau de bord."""
    if 'user_id' not in session:
        flash('Veuillez vous connecter.', 'warning')
        return redirect(url_for('login'))
    
    manager = PasswordManager()
    passwords = manager.get_passwords(session['user_id'], session.get('master_password', ''))
    
    # Statistiques
    stats = {
        'total': len(passwords),
        'compromised': sum(1 for p in passwords if p['breach_count'] > 0),
        'average_strength': sum(p['strength_score'] for p in passwords) / max(len(passwords), 1),
        'categories': {}
    }
    
    for p in passwords:
        cat = p['category']
        stats['categories'][cat] = stats['categories'].get(cat, 0) + 1
    
    return render_template('dashboard.html', 
                         username=session.get('username'),
                         stats=stats,
                         passwords=passwords[:5])

@app.route('/add-password', methods=['GET', 'POST'])
def add_password():
    """Ajouter un mot de passe."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    manager = PasswordManager()
    
    if request.method == 'POST':
        service = request.form.get('service')
        username = request.form.get('username')
        password = request.form.get('password')
        url = request.form.get('url', '')
        category = request.form.get('category', 'Autre')
        notes = request.form.get('notes', '')
        
        if not service or not username or not password:
            flash('Les champs Service, Utilisateur et Mot de passe sont requis.', 'danger')
        else:
            pid = manager.add_password(
                session['user_id'],
                session.get('master_password', ''),
                service, username, password, url, category, notes
            )
            
            if pid:
                flash('Mot de passe ajouté avec succès !', 'success')
                return redirect(url_for('view_passwords'))
            else:
                flash('Erreur lors de l\'ajout.', 'danger')
    
    return render_template('add_password.html')

@app.route('/view-passwords')
def view_passwords():
    """Voir tous les mots de passe."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    manager = PasswordManager()
    passwords = manager.get_passwords(session['user_id'], session.get('master_password', ''))
    
    # Logique de recherche et de filtrage de app2.py
    category = request.args.get('category', '')
    if category:
        passwords = [p for p in passwords if p['category'] == category]
    
    search = request.args.get('search', '')
    if search:
        passwords = [p for p in passwords 
                    if search.lower() in p['service'].lower() 
                    or search.lower() in p['username'].lower()]
    
    return render_template('view_passwords.html', passwords=passwords)

@app.route('/generator', methods=['GET', 'POST'])
def generator():
    """Générateur de mots de passe."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    manager = PasswordManager()
    generated_password = None
    breach_check = None
    
    if request.method == 'POST':
        length = int(request.form.get('length', 16))
        use_lower = 'lowercase' in request.form
        use_upper = 'uppercase' in request.form
        use_digits = 'digits' in request.form
        use_symbols = 'symbols' in request.form
        
        generated_password = manager.generate_password(
            length, use_lower, use_upper, use_digits, use_symbols
        )
        
        # Vérifier les fuites
        breach_check = manager.check_breaches(generated_password)
    
    return render_template('generator.html', 
                         generated_password=generated_password,
                         breach_check=breach_check)

@app.route('/edit-password/<int:password_id>', methods=['GET', 'POST'])
def edit_password(password_id):
    """Modifier un mot de passe existant (Route de app.py)."""
    if 'user_id' not in session:
        flash('Veuillez vous connecter.', 'warning')
        return redirect(url_for('login'))
    
    manager = PasswordManager()
    
    # Récupérer le mot de passe à modifier
    password_data = manager.get_password_by_id(
        session['user_id'],
        session.get('master_password', ''),
        password_id
    )
    
    if not password_data:
        flash('Mot de passe non trouvé.', 'danger')
        return redirect(url_for('view_passwords'))
    
    if request.method == 'POST':
        service = request.form.get('service')
        username = request.form.get('username')
        password = request.form.get('password')
        url = request.form.get('url', '')
        category = request.form.get('category', 'Autre')
        notes = request.form.get('notes', '')
        
        if not service or not username or not password:
            flash('Les champs Service, Utilisateur et Mot de passe sont requis.', 'danger')
        else:
            success = manager.update_password(
                session['user_id'],
                session.get('master_password', ''),
                password_id,
                service, username, password, url, category, notes
            )
            
            if success:
                flash('Mot de passe modifié avec succès !', 'success')
                return redirect(url_for('view_passwords'))
            else:
                flash('Erreur lors de la modification.', 'danger')
    
    return render_template('edit_password.html', password=password_data)

@app.route('/delete-password/<int:password_id>', methods=['POST'])
def delete_password(password_id):
    """Supprimer un mot de passe (Route de app.py)."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Non authentifié'}), 401

    manager = PasswordManager()
    success = manager.delete_password(session['user_id'], password_id)

    if success:
        flash('Mot de passe supprimé avec succès.', 'success')
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Mot de passe non trouvé'}), 404

@app.route('/view-password/<int:password_id>')
def view_password(password_id):
    """Voir les détails d'un mot de passe spécifique (Route de app.py)."""
    if 'user_id' not in session:
        flash('Veuillez vous connecter.', 'warning')
        return redirect(url_for('login'))

    manager = PasswordManager()
    password_data = manager.get_password_by_id(
        session['user_id'],
        session.get('master_password', ''),
        password_id
    )

    if not password_data:
        flash('Mot de passe non trouvé.', 'danger')
        return redirect(url_for('view_passwords'))

    return render_template('view_password.html', password=password_data)

@app.route('/api/generate', methods=['POST'])
def api_generate():
    """API pour générer un mot de passe."""
    try:
        data = request.json
        length = data.get('length', 16)
        use_lower = data.get('lowercase', True)
        use_upper = data.get('uppercase', True)
        use_digits = data.get('digits', True)
        use_symbols = data.get('symbols', True)
        
        manager = PasswordManager()
        password = manager.generate_password(length, use_lower, use_upper, use_digits, use_symbols)
        
        # La réponse de app.py est plus complète
        return jsonify({
            'password': password,
            'length': len(password),
            'breach_count': manager.check_breaches(password),
            'strength': manager.calculate_strength(password),
            'success': True
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500

@app.route('/api/check', methods=['POST'])
def api_check():
    """API pour vérifier un mot de passe."""
    try:
        data = request.json
        password = data.get('password', '')
        
        manager = PasswordManager()
        breach_count = manager.check_breaches(password)
        strength = manager.calculate_strength(password)
        
        # La réponse de app.py est plus complète
        return jsonify({
            'breach_count': breach_count,
            'strength': strength,
            'status': 'safe' if breach_count == 0 else 'compromised',
            'success': True
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500

@app.route('/settings')
def settings():
    """Paramètres."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('settings.html')

@app.route('/export-backup', methods=['GET'])
def export_backup():
    """Exporte une sauvegarde chiffrée (Route de app.py)."""
    if 'user_id' not in session:
        flash('Veuillez vous connecter.', 'warning')
        return redirect(url_for('login'))
    
    try:
        manager = PasswordManager()
        
        # Récupère les mots de passe
        passwords = manager.get_passwords(
            session['user_id'], 
            session.get('master_password', '')
        )
        
        if not passwords:
            flash('Aucun mot de passe à exporter.', 'info')
            return redirect(url_for('settings'))
        
        # Crée les données de sauvegarde
        backup_data = {
            'metadata': {
                'export_date': datetime.now().isoformat(),
                'username': session.get('username'),
                'user_id': session['user_id'],
                'total_passwords': len(passwords),
                'version': '1.0',
                'app': 'Password Manager Web'
            },
            'passwords': passwords
        }
        
        # Convertit en JSON
        json_data = json.dumps(backup_data, indent=2, ensure_ascii=False)
        
        # Chiffre avec le mot de passe maître
        master_password = session.get('master_password', '')
        
        # Utilise un chiffrement simple (XOR avec hash du mot de passe)
        key = hashlib.sha256(master_password.encode()).digest()
        
        # Chiffrement XOR
        encrypted = bytearray()
        for i, char in enumerate(json_data.encode()):
            encrypted.append(char ^ key[i % len(key)])
        
        # Ajoute un header pour identification
        header = b'PMBACKUPv1.0'
        final_data = header + bytes(encrypted)
        
        # Crée un nom de fichier
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        username = session.get('username', 'user').replace(' ', '_')
        filename = f'password_backup_{username}_{timestamp}.pmb'
        
        # Retourne le fichier
        return send_file(
            io.BytesIO(final_data),
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        flash(f'Erreur lors de l\'export : {str(e)}', 'danger')
        return redirect(url_for('settings'))

@app.route('/import-backup', methods=['POST'])
def import_backup():
    """Importe une sauvegarde (Route de app.py)."""
    if 'user_id' not in session:
        flash('Veuillez vous connecter.', 'warning')
        return redirect(url_for('login'))
    
    if 'backup_file' not in request.files:
        flash('Aucun fichier sélectionné.', 'danger')
        return redirect(url_for('settings'))
    
    file = request.files['backup_file']
    backup_password = request.form.get('backup_password')
    
    if not file or file.filename == '':
        flash('Aucun fichier sélectionné.', 'danger')
        return redirect(url_for('settings'))
    
    if not backup_password:
        flash('Mot de passe requis.', 'danger')
        return redirect(url_for('settings'))
    
    try:
        # Lit le fichier
        file_data = file.read()
        
        # Vérifie le header
        if not file_data.startswith(b'PMBACKUPv1.0'):
            flash('Format de fichier invalide.', 'danger')
            return redirect(url_for('settings'))
        
        # Enlève le header
        encrypted_data = file_data[12:]  # 12 = len('PMBACKUPv1.0')
        
        # Déchiffre
        key = hashlib.sha256(backup_password.encode()).digest()
        
        # Déchiffrement XOR
        decrypted = bytearray()
        for i, char in enumerate(encrypted_data):
            decrypted.append(char ^ key[i % len(key)])
        
        # Convertit en JSON
        backup_data = json.loads(decrypted.decode())
        
        # Vérifie la structure
        if 'passwords' not in backup_data:
            flash('Format de fichier invalide.', 'danger')
            return redirect(url_for('settings'))
        
        # Importe les mots de passe
        manager = PasswordManager()
        imported_count = 0
        skipped_count = 0
        
        for pwd_data in backup_data['passwords']:
            # Vérifie les champs requis
            if all(field in pwd_data for field in ['service', 'username', 'password']):
                try:
                    # Récupère les mots de passe existants pour vérifier les doublons
                    existing_passwords = manager.get_passwords(
                        session['user_id'], 
                        session.get('master_password', '')
                    )
                    
                    # Vérifie les doublons (basé sur service et username)
                    is_duplicate = any(
                        p['service'] == pwd_data['service'] and 
                        p['username'] == pwd_data['username']
                        for p in existing_passwords
                    )
                    
                    if not is_duplicate:
                        pid = manager.add_password(
                            session['user_id'],
                            session.get('master_password', ''),
                            pwd_data['service'],
                            pwd_data['username'],
                            pwd_data['password'],
                            pwd_data.get('url', ''),
                            pwd_data.get('category', 'Autre'),
                            pwd_data.get('notes', '')
                        )
                        if pid:
                            imported_count += 1
                        else:
                            skipped_count += 1
                    else:
                        skipped_count += 1
                except Exception as e:
                    print(f"Erreur import: {e}")
                    skipped_count += 1
        
        if imported_count > 0:
            flash(f'{imported_count} mots de passe importés avec succès ! ({skipped_count} ignorés)', 'success')
        else:
            flash('Aucun nouveau mot de passe importé.', 'info')
        
        return redirect(url_for('view_passwords'))
        
    except json.JSONDecodeError:
        flash('Fichier corrompu ou mot de passe incorrect.', 'danger')
    except Exception as e:
        flash(f'Erreur lors de l\'import : {str(e)}', 'danger')
    
    return redirect(url_for('settings'))

@app.route('/logout')
def logout():
    """Déconnexion."""
    # Nettoyer toutes les sessions, y compris les sessions 2FA en attente
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('master_password', None)
    session.pop('user_id_pending', None)
    session.pop('username_pending', None)
    session.pop('master_password_pending', None)
    
    flash('Déconnexion réussie.', 'info')
    return redirect(url_for('index'))

#  GESTION DES ERREURS 

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500

# POINT D'ENTRÉE 

if __name__ == '__main__':
    # Initialiser la base de données
    manager = PasswordManager()
    
    # Démarrer le serveur
    print("\n" + "=" * 50)
    print(" LANCEMENT DE PASSWORD MANAGER WEB")
    print("=" * 50)
    print(f" Serveur démarré sur: http://localhost:5000")
    print(" Base de données: data/passwords.db")
    print(" Mode debug: ACTIF")
    print("\nAppuyez sur Ctrl+C pour arrêter")
    print("=" * 50 + "\n")
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
    except KeyboardInterrupt:
        print("\n Arrêt du serveur")
    except Exception as e:
        print(f"\n Erreur: {e}")
