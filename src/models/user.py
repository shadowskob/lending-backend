from src.main import db, User

def create_admin_user():
    """
    Створює адміністратора, якщо він не існує
    """
    from werkzeug.security import generate_password_hash
    
    admin = User.query.filter_by(email='admin@lending.ua').first()
    if not admin:
        admin = User(
            email='admin@lending.ua',
            password=generate_password_hash('admin123'),
            name='Administrator',
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        print("Адміністратор створений успішно!")
    else:
        print("Адміністратор вже існує.")
