from src.main import app, db
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from src.models.user import User

user_bp = Blueprint('user', __name__)

@user_bp.route('/api/users/profile', methods=['GET'])
@login_required
def get_profile():
    """
    Отримати профіль поточного користувача
    """
    return jsonify({
        'id': current_user.id,
        'email': current_user.email,
        'name': current_user.name,
        'is_admin': current_user.is_admin
    }), 200

@user_bp.route('/api/users/profile', methods=['PUT'])
@login_required
def update_profile():
    """
    Оновити профіль поточного користувача
    """
    data = request.get_json()
    
    current_user.name = data.get('name', current_user.name)
    
    # Якщо змінюється email, перевірити, що він унікальний
    new_email = data.get('email')
    if new_email and new_email != current_user.email:
        if User.query.filter_by(email=new_email).first():
            return jsonify({'error': 'Email already exists'}), 400
        current_user.email = new_email
    
    db.session.commit()
    
    return jsonify({
        'message': 'Profile updated successfully',
        'user': {
            'id': current_user.id,
            'email': current_user.email,
            'name': current_user.name
        }
    }), 200

@user_bp.route('/api/users/password', methods=['PUT'])
@login_required
def change_password():
    """
    Змінити пароль поточного користувача
    """
    from werkzeug.security import generate_password_hash, check_password_hash
    
    data = request.get_json()
    
    if not check_password_hash(current_user.password, data['current_password']):
        return jsonify({'error': 'Current password is incorrect'}), 400
    
    current_user.password = generate_password_hash(data['new_password'])
    db.session.commit()
    
    return jsonify({'message': 'Password changed successfully'}), 200

# Реєстрація Blueprint в додатку
app.register_blueprint(user_bp)
