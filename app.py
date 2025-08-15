# mcs-vinicius/projecttoxicos/projectToxicos-main/Backend/App.py

from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps
from datetime import datetime, date
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
import decimal
import json
import secrets
import string

app = Flask(__name__)

# --- Configurações Iniciais ---
prod_origin = os.environ.get('FRONTEND_URL', 'https://hml-toxicos-frontend.vercel.app')
CORS(
    app,
    origins=prod_origin if prod_origin else "*",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    supports_credentials=True,
    expose_headers=["Content-Type", "Authorization"]
)

app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Modelos do Banco de Dados ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='member')
    habby_id = db.Column(db.String(50), unique=True)
    profile = db.relationship('UserProfile', backref='user', uselist=False, cascade="all, delete-orphan")

class UserProfile(db.Model):
    __tablename__ = 'user_profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    habby_id = db.Column(db.String(50), unique=True, nullable=False)
    nick = db.Column(db.String(100))
    profile_pic_url = db.Column(db.String(512), default="https://ik.imagekit.io/wzl99vhez/toxicos/indefinido.png?updatedAt=1750707356953")
    atk = db.Column(db.Integer)
    hp = db.Column(db.Integer)
    survivor_base_atk = db.Column(db.Integer)
    survivor_base_hp = db.Column(db.Integer)
    survivor_bonus_atk = db.Column(db.Numeric(5, 2))
    survivor_bonus_hp = db.Column(db.Numeric(5, 2))
    survivor_final_atk = db.Column(db.Integer)
    survivor_final_hp = db.Column(db.Integer)
    survivor_crit_rate = db.Column(db.Numeric(5, 2))
    survivor_crit_damage = db.Column(db.Numeric(5, 2))
    survivor_skill_damage = db.Column(db.Numeric(5, 2))
    survivor_shield_boost = db.Column(db.Numeric(5, 2))
    survivor_poison_targets = db.Column(db.Numeric(5, 2))
    survivor_weak_targets = db.Column(db.Numeric(5, 2))
    survivor_frozen_targets = db.Column(db.Numeric(5, 2))
    pet_base_atk = db.Column(db.Integer)
    pet_base_hp = db.Column(db.Integer)
    pet_crit_damage = db.Column(db.Numeric(5, 2))
    pet_skill_damage = db.Column(db.Numeric(5, 2))
    collect_final_atk = db.Column(db.Integer)
    collect_final_hp = db.Column(db.Integer)
    collect_crit_rate = db.Column(db.Numeric(5, 2))
    collect_crit_damage = db.Column(db.Numeric(5, 2))
    collect_skill_damage = db.Column(db.Numeric(5, 2))
    collect_poison_targets = db.Column(db.Numeric(5, 2))
    collect_weak_targets = db.Column(db.Numeric(5, 2))
    collect_frozen_targets = db.Column(db.Numeric(5, 2))

class Season(db.Model):
    __tablename__ = 'seasons'
    id = db.Column(db.Integer, primary_key=True)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    participants = db.relationship('Participant', backref='season', cascade="all, delete-orphan")

class Participant(db.Model):
    __tablename__ = 'participants'
    id = db.Column(db.Integer, primary_key=True)
    season_id = db.Column(db.Integer, db.ForeignKey('seasons.id', ondelete='CASCADE'), nullable=False)
    habby_id = db.Column(db.String(50))
    name = db.Column(db.String(100), nullable=False)
    fase = db.Column(db.Integer, nullable=False)
    r1 = db.Column(db.Integer, nullable=False)
    r2 = db.Column(db.Integer, nullable=False)
    r3 = db.Column(db.Integer, nullable=False)
    
    @property
    def total(self):
        return self.r1 + self.r2 + self.r3

class HomeContent(db.Model):
    __tablename__ = 'home_content'
    id = db.Column(db.Integer, primary_key=True, default=1)
    leader = db.Column(db.String(255))
    focus = db.Column(db.String(255))
    league = db.Column(db.String(255))
    requirements = db.Column(db.Text)
    content_section = db.Column(db.Text)

class HonorSeason(db.Model):
    __tablename__ = 'honor_seasons'
    id = db.Column(db.Integer, primary_key=True)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    participants = db.relationship('HonorParticipant', backref='season', cascade="all, delete-orphan", order_by="HonorParticipant.sort_order")

class HonorParticipant(db.Model):
    __tablename__ = 'honor_participants'
    id = db.Column(db.Integer, primary_key=True)
    season_id = db.Column(db.Integer, db.ForeignKey('honor_seasons.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    habby_id = db.Column(db.String(50), nullable=False)
    fase_acesso = db.Column(db.String(10), nullable=False)
    fase_ataque = db.Column(db.String(10), nullable=False)
    sort_order = db.Column(db.Integer, nullable=False)

# <<< NOVO MODELO PARA O JOGO DA COBRINHA >>>
class SnakeScore(db.Model):
    __tablename__ = 'snake_scores'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    difficulty = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.now())
    # NOVO CAMPO para registrar a vitória
    completed_game = db.Column(db.Boolean, default=False)

# --- Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Acesso não autorizado.'}), 401
        return f(*args, **kwargs)
    return decorated_function

def roles_required(allowed_roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Acesso não autorizado.'}), 401
            if session.get('role') not in allowed_roles:
                return jsonify({'error': 'Permissão insuficiente.'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

# --- Funções Auxiliares ---
def normalize_status(value):
    if isinstance(value, str) and value.strip().lower().startswith('s'):
        return 'Sim'
    return 'Não'
    
def model_to_dict(obj):
    if obj is None:
        return None
    data = {}
    for column in obj.__table__.columns:
        value = getattr(obj, column.name)
        if isinstance(value, (datetime, date)):
            data[column.name] = value.isoformat()
        elif isinstance(value, decimal.Decimal):
            data[column.name] = str(value)
        else:
            data[column.name] = value
    return data

# --- ROTAS DE AUTENTICAÇÃO E USUÁRIO ---
@app.route('/register-user', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    habby_id = data.get('habby_id')

    if not all([username, password, habby_id]):
        return jsonify({'error': 'Nome de usuário, senha e ID Habby são obrigatórios'}), 400

    if User.query.filter((User.username == username) | (User.habby_id == habby_id)).first():
        return jsonify({'error': 'Nome de usuário ou ID Habby já existem.'}), 409

    role = 'admin' if not User.query.filter_by(role='admin').first() else 'member'
    hashed_password = generate_password_hash(password)
    
    try:
        new_user = User(username=username, password=hashed_password, role=role, habby_id=habby_id)
        new_profile = UserProfile(user=new_user, habby_id=habby_id, nick=username)
        db.session.add(new_user)
        db.session.add(new_profile)
        db.session.commit()
        return jsonify({'message': f'Usuário cadastrado com sucesso como {role}!'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Erro ao cadastrar usuário: {e}'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        session['logged_in'] = True
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        session['habby_id'] = user.habby_id
        return jsonify({
            'message': 'Login bem-sucedido!',
            'user': { 'id': user.id, 'username': user.username, 'role': user.role, 'habby_id': user.habby_id }
        }), 200
    else:
        return jsonify({'error': 'Credenciais inválidas'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logout bem-sucedido'}), 200

@app.route('/session', methods=['GET'])
def get_session():
    if 'user_id' in session:
        return jsonify({
            'isLoggedIn': True,
            'user': { 'id': session['user_id'], 'username': session['username'], 'role': session.get('role'), 'habby_id': session.get('habby_id') }
        }), 200
    return jsonify({'isLoggedIn': False}), 200

# --- ROTAS DE GERENCIAMENTO ---
@app.route('/users', methods=['GET'])
@roles_required(['admin', 'leader'])
def get_users():
    users_data = db.session.query(
        User.id, User.username, User.role, UserProfile.habby_id, UserProfile.nick, UserProfile.profile_pic_url
    ).join(UserProfile, User.id == UserProfile.user_id).order_by(User.role, User.username).all()
    
    users = [{'id': u.id, 'username': u.username, 'role': u.role, 'habby_id': u.habby_id, 'nick': u.nick, 'profile_pic_url': u.profile_pic_url} for u in users_data]
    return jsonify(users), 200

@app.route('/users/<int:user_id>/role', methods=['PUT'])
@roles_required(['admin'])
def update_user_role(user_id):
    data = request.json
    new_role = data.get('role')

    if new_role not in ['member', 'leader']: return jsonify({'error': 'Role inválida.'}), 400
    if session.get('user_id') == user_id: return jsonify({'error': 'O administrador não pode alterar seu próprio nível.'}), 403

    user = User.query.get(user_id)
    if not user: return jsonify({'error': 'Usuário não encontrado.'}), 404

    try:
        user.role = new_role
        db.session.commit()
        return jsonify({'message': 'Nível de acesso atualizado com sucesso!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Erro ao atualizar role: {e}'}), 500

@app.route('/users/<int:user_id>', methods=['DELETE'])
@roles_required(['admin', 'leader'])
def delete_user(user_id):
    logged_in_user_role = session.get('role')
    logged_in_user_id = session.get('user_id')

    if user_id == logged_in_user_id: return jsonify({'error': 'Você não pode excluir a si mesmo.'}), 403

    user_to_delete = User.query.get(user_id)
    if not user_to_delete: return jsonify({'error': 'Usuário não encontrado.'}), 404

    if logged_in_user_role == 'leader' and user_to_delete.role in ['leader', 'admin']:
        return jsonify({'error': 'Líderes só podem excluir membros.'}), 403

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        return jsonify({'message': 'Usuário excluído com sucesso!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Erro ao excluir usuário: {e}'}), 500

@app.route('/users/<int:user_id>/reset-password', methods=['POST'])
@roles_required(['admin'])
def reset_password(user_id):
    user = User.query.get(user_id)
    if not user: return jsonify({'error': 'Usuário não encontrado.'}), 404
    if user.role == 'admin' and session.get('user_id') != user.id: return jsonify({'error': 'Não é permitido redefinir a senha de outro administrador.'}), 403

    try:
        alphabet = string.ascii_letters + string.digits
        temp_password = ''.join(secrets.choice(alphabet) for i in range(10))
        user.password = generate_password_hash(temp_password)
        db.session.commit()
        return jsonify({'message': f'Senha para o usuário {user.username} redefinida com sucesso!', 'temporary_password': temp_password}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Erro ao redefinir a senha: {e}'}), 500

# --- ROTAS DE PERFIL E BUSCA ---
@app.route('/search-users', methods=['GET'])
@login_required
def search_users():
    query = request.args.get('query', '')
    if len(query) < 2: return jsonify([])
    search_query = f"%{query}%"
    users = UserProfile.query.filter(or_(UserProfile.nick.ilike(search_query), UserProfile.habby_id.ilike(search_query))).limit(10).all()
    return jsonify([{'habby_id': u.habby_id, 'nick': u.nick} for u in users])

@app.route('/profile/<string:habby_id>', methods=['GET'])
@login_required
def get_user_profile(habby_id):
    profile = UserProfile.query.filter_by(habby_id=habby_id).first()
    if not profile: return jsonify({'error': 'Perfil não encontrado.'}), 404
    return jsonify(model_to_dict(profile))

@app.route('/profile', methods=['PUT'])
@login_required
def update_user_profile():
    data = request.json
    logged_in_habby_id = session.get('habby_id')
    profile = UserProfile.query.filter_by(habby_id=logged_in_habby_id).first()
    if not profile: return jsonify({'error': 'Perfil não encontrado.'}), 404

    updatable_fields = [ 'nick', 'profile_pic_url', 'atk', 'hp', 'survivor_base_atk', 'survivor_base_hp', 'survivor_bonus_atk', 'survivor_bonus_hp', 'survivor_final_atk', 'survivor_final_hp', 'survivor_crit_rate', 'survivor_crit_damage', 'survivor_skill_damage', 'survivor_shield_boost', 'survivor_poison_targets', 'survivor_weak_targets', 'survivor_frozen_targets', 'pet_base_atk', 'pet_base_hp', 'pet_crit_damage', 'pet_skill_damage', 'collect_final_atk', 'collect_final_hp', 'collect_crit_rate', 'collect_crit_damage', 'collect_skill_damage', 'collect_poison_targets', 'collect_weak_targets', 'collect_frozen_targets' ]
    
    if 'new_password' in data and data['new_password']:
        user_to_update = User.query.filter_by(habby_id=logged_in_habby_id).first()
        if user_to_update:
            user_to_update.password = generate_password_hash(data['new_password'])

    for field in updatable_fields:
        if field in data:
            setattr(profile, field, data[field])
    
    try:
        db.session.commit()
        return jsonify({'message': 'Perfil atualizado com sucesso!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Erro ao atualizar perfil: {e}'}), 500

# --- ROTAS DE TEMPORADA E HONRA ---
@app.route('/seasons', methods=['GET'])
def get_seasons():
    seasons = Season.query.order_by(Season.start_date.asc()).all()
    result = []
    for s in seasons:
        participants_data = [{'id': p.id, 'habby_id': p.habby_id, 'name': p.name, 'fase': p.fase, 'r1': p.r1, 'r2': p.r2, 'r3': p.r3, 'total': p.total} for p in s.participants]
        result.append({'id': s.id, 'start_date': s.start_date.isoformat(), 'end_date': s.end_date.isoformat(), 'participants': participants_data})
    return jsonify(result)

@app.route('/seasons', methods=['POST'])
@roles_required(['admin', 'leader'])
def create_season():
    data = request.json
    start_date_str, end_date_str, participants_data = data.get('startDate'), data.get('endDate'), data.get('participants', [])
    if not start_date_str or not end_date_str: return jsonify({'error': 'Data de início e fim obrigatórias'}), 400

    try:
        new_season = Season(start_date=datetime.strptime(start_date_str, '%Y-%m-%d').date(), end_date=datetime.strptime(end_date_str, '%Y-%m-%d').date())
        db.session.add(new_season); db.session.flush()
        for p_data in participants_data:
            db.session.add(Participant(season_id=new_season.id, habby_id=p_data.get('habby_id'), name=p_data['name'], fase=p_data['fase'], r1=p_data['r1'], r2=p_data['r2'], r3=p_data['r3']))
        db.session.commit()
        return jsonify({'message': 'Temporada criada com sucesso!', 'seasonId': new_season.id}), 201
    except Exception as e:
        db.session.rollback(); return jsonify({'error': f'Erro ao criar temporada: {e}'}), 500

@app.route('/seasons/<int:season_id>', methods=['DELETE'])
@roles_required(['admin'])
def delete_season(season_id):
    season = Season.query.get(season_id)
    if not season: return jsonify({'error': 'Temporada não encontrada.'}), 404
    try:
        db.session.delete(season); db.session.commit()
        return jsonify({'message': 'Temporada e todos os seus registros foram excluídos com sucesso!'}), 200
    except Exception as e:
        db.session.rollback(); return jsonify({'error': f'Erro ao excluir a temporada: {e}'}), 500

# --- ROTA DE HISTÓRICO ---
@app.route('/history/<string:habby_id>', methods=['GET'])
@login_required
def get_user_history(habby_id):
    try:
        participations = db.session.query(Season.id.label('season_id'), Season.start_date, Participant.fase).join(Participant, Season.id == Participant.season_id).filter(Participant.habby_id == habby_id).order_by(Season.start_date.desc()).all()
        if not participations: return jsonify({}), 200
        
        latest = participations[0]
        season_ranking = Participant.query.filter_by(season_id=latest.season_id).order_by(Participant.fase.desc(), (Participant.r1 + Participant.r2 + Participant.r3).desc()).all()
        position = next((i + 1 for i, p in enumerate(season_ranking) if p.habby_id == habby_id), None)
        
        evolution = 0
        if len(participations) > 1:
            previous = participations[1]
            if latest.fase is not None and previous.fase is not None:
                evolution = latest.fase - previous.fase
        
        return jsonify({'position': position, 'fase_acesso': latest.fase, 'evolution': evolution})
    except Exception as e:
        return jsonify({'error': 'Erro ao buscar histórico.'}), 500

# --- ROTAS DE HONRA ---
@app.route('/honor-members-management', methods=['GET'])
@roles_required(['admin', 'leader'])
def get_honor_management_list():
    latest_season = HonorSeason.query.order_by(HonorSeason.start_date.desc()).first()
    if not latest_season: return jsonify([])
    return jsonify([{'name': p.name, 'habby_id': p.habby_id, 'fase_acesso': p.fase_acesso, 'fase_ataque': p.fase_ataque} for p in latest_season.participants])

@app.route('/honor-seasons', methods=['POST'])
@roles_required(['admin', 'leader'])
def create_honor_season():
    data = request.json
    start_date_str, end_date_str, participants_data = data.get('startDate'), data.get('endDate'), data.get('participants', [])
    if not start_date_str or not end_date_str or not participants_data: return jsonify({'error': 'Datas e participantes são obrigatórios.'}), 400
    try:
        new_season = HonorSeason(start_date=datetime.strptime(start_date_str, '%Y-%m-%d').date(), end_date=datetime.strptime(end_date_str, '%Y-%m-%d').date())
        db.session.add(new_season); db.session.flush()
        for i, p_data in enumerate(participants_data):
            db.session.add(HonorParticipant(season_id=new_season.id, name=p_data['name'], habby_id=p_data['habby_id'], fase_acesso=normalize_status(p_data.get('fase_acesso')), fase_ataque=normalize_status(p_data.get('fase_ataque')), sort_order=i))
        db.session.commit()
        return jsonify({'message': 'Nova temporada de Honra criada com sucesso!', 'seasonId': new_season.id}), 201
    except Exception as e:
        db.session.rollback(); return jsonify({'error': f'Erro ao criar nova temporada: {e}'}), 500

@app.route('/honor-seasons', methods=['GET'])
def get_honor_seasons():
    seasons = HonorSeason.query.order_by(HonorSeason.start_date.asc()).all()
    result = []
    for s in seasons:
        participants_data = [{'id': p.id, 'name': p.name, 'habby_id': p.habby_id, 'fase_acesso': p.fase_acesso, 'fase_ataque': p.fase_ataque} for p in s.participants]
        result.append({'id': s.id, 'start_date': s.start_date.isoformat(), 'end_date': s.end_date.isoformat(), 'participants': participants_data})
    return jsonify(result)

@app.route('/honor-seasons/<int:season_id>', methods=['DELETE'])
@roles_required(['admin'])
def delete_honor_season(season_id):
    season = HonorSeason.query.get(season_id)
    if not season: return jsonify({'error': 'Temporada de honra não encontrada.'}), 404
    try:
        db.session.delete(season); db.session.commit()
        return jsonify({'message': 'Temporada de honra excluída com sucesso!'}), 200
    except Exception as e:
        db.session.rollback(); return jsonify({'error': f'Erro ao excluir temporada de honra: {e}'}), 500

@app.route('/latest-honor-members', methods=['GET'])
def get_latest_honor_members():
    latest_season = HonorSeason.query.order_by(HonorSeason.start_date.desc()).first()
    if not latest_season: return jsonify({'members': [], 'period': 'Nenhuma temporada definida.'})
    
    top_members = db.session.query(HonorParticipant.name, HonorParticipant.habby_id, UserProfile.profile_pic_url).outerjoin(UserProfile, UserProfile.habby_id == HonorParticipant.habby_id).filter(HonorParticipant.season_id == latest_season.id).order_by(HonorParticipant.sort_order.asc()).limit(2).all()
    members = [{'name': p.name, 'habby_id': p.habby_id, 'profile_pic_url': p.profile_pic_url or "https://ik.imagekit.io/wzl99vhez/toxicos/indefinido.png?updatedAt=1750707356953"} for p in top_members]
    period = f"De: {latest_season.start_date.strftime('%d/%m/%Y')} a Até: {latest_season.end_date.strftime('%d/%m/%Y')}"
    return jsonify({'members': members, 'period': period})

@app.route('/honor-status/<string:habby_id>', methods=['GET'])
def get_honor_status(habby_id):
    latest_season = HonorSeason.query.order_by(HonorSeason.start_date.desc()).first()
    if not latest_season: return jsonify({'is_honor_member': False})
    
    is_member = HonorParticipant.query.filter(HonorParticipant.season_id == latest_season.id, HonorParticipant.habby_id == habby_id, HonorParticipant.sort_order < 2).first() is not None
    return jsonify({'is_honor_member': is_member})

# --- ROTAS DE CONTEÚDO DA HOME ---
@app.route('/home-content', methods=['GET'])
def get_home_content():
    content = HomeContent.query.get(1)
    if content:
        return jsonify({'leader': content.leader, 'focus': content.focus, 'league': content.league, 'requirements': content.requirements.split(';') if content.requirements else [], 'content_section': content.content_section})
    return jsonify({'error': 'Conteúdo não encontrado.'}), 404

@app.route('/home-content', methods=['PUT'])
@roles_required(['admin'])
def update_home_content():
    data, content = request.json, HomeContent.query.get(1)
    if not content: return jsonify({'error': 'Conteúdo não encontrado para atualizar.'}), 404
    try:
        content.leader, content.focus, content.league, content.requirements, content.content_section = data.get('leader'), data.get('focus'), data.get('league'), ';'.join(data.get('requirements', [])), data.get('content_section')
        db.session.commit()
        return jsonify({'message': 'Conteúdo da Home atualizado com sucesso!'})
    except Exception as e:
        db.session.rollback(); return jsonify({'error': f'Erro ao atualizar conteúdo: {e}'}), 500

# <<< ROTAS PARA O JOGO DA COBRINHA >>>
@app.route('/snake-scores', methods=['GET'])
def get_snake_scores():
    try:
        scores = SnakeScore.query.order_by(SnakeScore.score.desc()).limit(10).all()
        return jsonify([{'username': s.username, 'score': s.score, 'difficulty': s.difficulty, 'completed_game': s.completed_game} for s in scores])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/snake-scores', methods=['POST'])
@login_required
def add_snake_score():
    data = request.get_json()
    new_score, difficulty, completed = data.get('score'), data.get('difficulty'), data.get('completed', False)
    if new_score is None or not difficulty: return jsonify({'error': 'Dados incompletos'}), 400
    
    user = User.query.get(session.get('user_id'))
    if not user: return jsonify({'error': 'Usuário da sessão não encontrado.'}), 403

    try:
        existing_score = SnakeScore.query.filter_by(user_id=user.id).first()
        if existing_score:
            if new_score > existing_score.score:
                existing_score.score, existing_score.difficulty, existing_score.created_at = new_score, difficulty, datetime.utcnow()
                if completed: existing_score.completed_game = True
                db.session.commit()
                return jsonify({'message': 'Sua pontuação recorde foi atualizada!'}), 200
            else:
                if completed and not existing_score.completed_game:
                    existing_score.completed_game = True
                    db.session.commit()
                    return jsonify({'message': 'Status de vitória atualizado!'}), 200
                return jsonify({'message': 'Pontuação não superou o recorde anterior.'}), 200
        else:
            db.session.add(SnakeScore(user_id=user.id, username=user.username, score=new_score, difficulty=difficulty, completed_game=completed))
            db.session.commit()
            return jsonify({'message': 'Pontuação salva com sucesso!'}), 201
    except Exception as e:
        db.session.rollback(); return jsonify({'error': f'Erro ao salvar pontuação: {e}'}), 500

# --- ROTAS DE BACKUP E RESTAURAÇÃO ---
@app.route('/backup', methods=['GET'])
@roles_required(['admin'])
def backup_data():
    try:
        participants_list = []
        for p in Participant.query.all():
            p_dict = model_to_dict(p); p_dict['total'] = p.total; participants_list.append(p_dict)
        
        full_backup = {
            'users': [model_to_dict(u) for u in User.query.all()],
            'user_profiles': [model_to_dict(up) for up in UserProfile.query.all()],
            'seasons': [model_to_dict(s) for s in Season.query.all()],
            'participants': participants_list,
            'home_content': [model_to_dict(hc) for hc in HomeContent.query.all()],
            'honor_seasons': [model_to_dict(hs) for hs in HonorSeason.query.all()],
            'honor_participants': [model_to_dict(hp) for hp in HonorParticipant.query.all()],
            'snake_scores': [model_to_dict(ss) for ss in SnakeScore.query.all()],
        }
        return jsonify(full_backup)
    except Exception as e:
        return jsonify({'error': 'Ocorreu um erro interno ao gerar o backup.', 'details': str(e)}), 500

@app.route('/restore', methods=['POST'])
@roles_required(['admin'])
def restore_data():
    if 'file' not in request.files: return jsonify({'error': 'Nenhum arquivo enviado.'}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({'error': 'Nenhum arquivo selecionado.'}), 400

    try:
        data = json.load(file)
        # Limpa todas as tabelas na ordem correta
        db.session.query(SnakeScore).delete()
        db.session.query(HonorParticipant).delete()
        db.session.query(Participant).delete()
        db.session.query(UserProfile).delete()
        db.session.query(User).delete()
        db.session.query(HonorSeason).delete()
        db.session.query(Season).delete()
        db.session.query(HomeContent).delete()
        db.session.commit()

        # Restaura os dados
        for user_data in data.get('users', []): db.session.add(User(**user_data))
        for profile_data in data.get('user_profiles', []): db.session.add(UserProfile(**profile_data))
        db.session.commit()

        for s_data in data.get('seasons', []):
            s_data.update({'start_date': date.fromisoformat(s_data['start_date']), 'end_date': date.fromisoformat(s_data['end_date'])}).pop('participants', None)
            db.session.add(Season(**s_data))
        for p_data in data.get('participants', []): p_data.pop('total', None); db.session.add(Participant(**p_data))
        for hc_data in data.get('home_content', []): db.session.add(HomeContent(**hc_data))
        for hs_data in data.get('honor_seasons', []):
            hs_data.update({'start_date': date.fromisoformat(hs_data['start_date']), 'end_date': date.fromisoformat(hs_data['end_date'])}).pop('participants', None)
            db.session.add(HonorSeason(**hs_data))
        for hp_data in data.get('honor_participants', []): db.session.add(HonorParticipant(**hp_data))
        for ss_data in data.get('snake_scores', []):
            if ss_data.get('created_at'): ss_data['created_at'] = datetime.fromisoformat(ss_data['created_at'])
            db.session.add(SnakeScore(**ss_data))
        
        db.session.commit()
        return jsonify({'message': 'Restauração concluída com sucesso!'}), 200
    except Exception as e:
        db.session.rollback(); return jsonify({'error': f'Erro ao restaurar dados: {e}'}), 500

# --- FUNÇÃO DE INICIALIZAÇÃO DO BANCO DE DADOS ---
def create_tables():
    with app.app_context():
        print("Criando/Verificando todas as tabelas no banco de dados...")
        db.create_all()
        print("Tabelas prontas.")
        
        if not HomeContent.query.get(1):
            print("Inserindo conteúdo inicial da Home...")
            db.session.add(HomeContent(id=1, leader='Líder a definir', focus='Foco a definir', league='Liga a definir', requirements='Requisito 1;Requisito 2', content_section='Seção de conteúdo a definir.'))
            db.session.commit()
            print("Conteúdo inicial inserido.")

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'init-db':
        create_tables()
    else:
        app.run(debug=True, port=int(os.environ.get('PORT', 5000)))