import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))  # DON'T CHANGE THIS !!!

from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import json
import datetime
import uuid
from dotenv import load_dotenv

# Завантаження змінних середовища
load_dotenv()

# Ініціалізація Flask додатку
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'lending-secret-key')

# Налаштування бази даних
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{os.getenv('DB_USERNAME', 'lending_user')}:{os.getenv('DB_PASSWORD', 'password')}@{os.getenv('DB_HOST', 'localhost')}:{os.getenv('DB_PORT', '5432')}/{os.getenv('DB_NAME', 'lending_db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Ініціалізація розширень
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
CORS(app)

# Моделі бази даних
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    orders = db.relationship('Order', backref='user', lazy=True)
    wishlist = db.relationship('WishlistItem', backref='user', lazy=True)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    products = db.relationship('Product', backref='category', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    old_price = db.Column(db.Float, nullable=True)
    image = db.Column(db.String(200), nullable=True)
    stock = db.Column(db.Integer, default=0)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    reviews = db.relationship('Review', backref='product', lazy=True)
    order_items = db.relationship('OrderItem', backref='product', lazy=True)
    wishlist_items = db.relationship('WishlistItem', backref='product', lazy=True)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), default='pending')
    total = db.Column(db.Float, nullable=False)
    shipping_address = db.Column(db.Text, nullable=False)
    shipping_method = db.Column(db.String(100), nullable=False)
    payment_method = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    items = db.relationship('OrderItem', backref='order', lazy=True)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user = db.relationship('User', backref='reviews')

class WishlistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class RepairRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    device_type = db.Column(db.String(100), nullable=False)
    device_model = db.Column(db.String(100), nullable=False)
    problem = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Маршрути API
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        email=data['email'],
        password=hashed_password,
        name=data['name']
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    
    if user and check_password_hash(user.password, data['password']):
        login_user(user)
        return jsonify({
            'id': user.id,
            'email': user.email,
            'name': user.name,
            'is_admin': user.is_admin
        }), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/auth/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/products', methods=['GET'])
def get_products():
    category_id = request.args.get('category_id')
    search = request.args.get('search')
    
    query = Product.query
    
    if category_id:
        query = query.filter_by(category_id=category_id)
    
    if search:
        query = query.filter(Product.name.ilike(f'%{search}%'))
    
    products = query.all()
    result = []
    
    for product in products:
        result.append({
            'id': product.id,
            'name': product.name,
            'description': product.description,
            'price': product.price,
            'old_price': product.old_price,
            'image': product.image,
            'stock': product.stock,
            'category_id': product.category_id
        })
    
    return jsonify(result), 200

@app.route('/api/products/<int:id>', methods=['GET'])
def get_product(id):
    product = Product.query.get_or_404(id)
    
    reviews = []
    for review in product.reviews:
        reviews.append({
            'id': review.id,
            'rating': review.rating,
            'comment': review.comment,
            'user_name': review.user.name,
            'created_at': review.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({
        'id': product.id,
        'name': product.name,
        'description': product.description,
        'price': product.price,
        'old_price': product.old_price,
        'image': product.image,
        'stock': product.stock,
        'category_id': product.category_id,
        'category_name': product.category.name,
        'reviews': reviews
    }), 200

@app.route('/api/products', methods=['POST'])
@login_required
def add_product():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    
    new_product = Product(
        name=data['name'],
        description=data.get('description', ''),
        price=data['price'],
        old_price=data.get('old_price'),
        image=data.get('image', ''),
        stock=data.get('stock', 0),
        category_id=data['category_id']
    )
    
    db.session.add(new_product)
    db.session.commit()
    
    return jsonify({
        'id': new_product.id,
        'name': new_product.name,
        'message': 'Product added successfully'
    }), 201

@app.route('/api/products/<int:id>', methods=['PUT'])
@login_required
def update_product(id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    product = Product.query.get_or_404(id)
    data = request.get_json()
    
    product.name = data.get('name', product.name)
    product.description = data.get('description', product.description)
    product.price = data.get('price', product.price)
    product.old_price = data.get('old_price', product.old_price)
    product.image = data.get('image', product.image)
    product.stock = data.get('stock', product.stock)
    product.category_id = data.get('category_id', product.category_id)
    
    db.session.commit()
    
    return jsonify({'message': 'Product updated successfully'}), 200

@app.route('/api/products/<int:id>', methods=['DELETE'])
@login_required
def delete_product(id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    product = Product.query.get_or_404(id)
    
    db.session.delete(product)
    db.session.commit()
    
    return jsonify({'message': 'Product deleted successfully'}), 200

@app.route('/api/categories', methods=['GET'])
def get_categories():
    categories = Category.query.all()
    result = []
    
    for category in categories:
        result.append({
            'id': category.id,
            'name': category.name,
            'slug': category.slug
        })
    
    return jsonify(result), 200

@app.route('/api/orders', methods=['GET'])
@login_required
def get_orders():
    if current_user.is_admin:
        orders = Order.query.all()
    else:
        orders = Order.query.filter_by(user_id=current_user.id).all()
    
    result = []
    
    for order in orders:
        items = []
        for item in order.items:
            items.append({
                'id': item.id,
                'product_id': item.product_id,
                'product_name': item.product.name,
                'quantity': item.quantity,
                'price': item.price
            })
        
        result.append({
            'id': order.id,
            'user_id': order.user_id,
            'user_name': order.user.name,
            'status': order.status,
            'total': order.total,
            'shipping_address': order.shipping_address,
            'shipping_method': order.shipping_method,
            'payment_method': order.payment_method,
            'created_at': order.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'items': items
        })
    
    return jsonify(result), 200

@app.route('/api/orders/<int:id>', methods=['GET'])
@login_required
def get_order(id):
    order = Order.query.get_or_404(id)
    
    if not current_user.is_admin and order.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    items = []
    for item in order.items:
        items.append({
            'id': item.id,
            'product_id': item.product_id,
            'product_name': item.product.name,
            'quantity': item.quantity,
            'price': item.price
        })
    
    return jsonify({
        'id': order.id,
        'user_id': order.user_id,
        'user_name': order.user.name,
        'status': order.status,
        'total': order.total,
        'shipping_address': order.shipping_address,
        'shipping_method': order.shipping_method,
        'payment_method': order.payment_method,
        'created_at': order.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'items': items
    }), 200

@app.route('/api/orders', methods=['POST'])
@login_required
def create_order():
    data = request.get_json()
    
    new_order = Order(
        user_id=current_user.id,
        total=data['total'],
        shipping_address=data['shipping_address'],
        shipping_method=data['shipping_method'],
        payment_method=data['payment_method']
    )
    
    db.session.add(new_order)
    db.session.commit()
    
    for item_data in data['items']:
        product = Product.query.get(item_data['product_id'])
        if not product or product.stock < item_data['quantity']:
            db.session.delete(new_order)
            db.session.commit()
            return jsonify({'error': 'Product out of stock'}), 400
        
        product.stock -= item_data['quantity']
        
        order_item = OrderItem(
            order_id=new_order.id,
            product_id=item_data['product_id'],
            quantity=item_data['quantity'],
            price=product.price
        )
        
        db.session.add(order_item)
    
    db.session.commit()
    
    return jsonify({
        'id': new_order.id,
        'message': 'Order created successfully'
    }), 201

@app.route('/api/orders/<int:id>/status', methods=['PUT'])
@login_required
def update_order_status(id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    order = Order.query.get_or_404(id)
    data = request.get_json()
    
    order.status = data['status']
    db.session.commit()
    
    return jsonify({'message': 'Order status updated successfully'}), 200

@app.route('/api/reviews', methods=['GET'])
def get_reviews():
    product_id = request.args.get('product_id')
    
    query = Review.query
    
    if product_id:
        query = query.filter_by(product_id=product_id)
    
    reviews = query.all()
    result = []
    
    for review in reviews:
        result.append({
            'id': review.id,
            'product_id': review.product_id,
            'user_id': review.user_id,
            'user_name': review.user.name,
            'rating': review.rating,
            'comment': review.comment,
            'created_at': review.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify(result), 200

@app.route('/api/reviews', methods=['POST'])
@login_required
def add_review():
    data = request.get_json()
    
    new_review = Review(
        product_id=data['product_id'],
        user_id=current_user.id,
        rating=data['rating'],
        comment=data.get('comment', '')
    )
    
    db.session.add(new_review)
    db.session.commit()
    
    return jsonify({
        'id': new_review.id,
        'message': 'Review added successfully'
    }), 201

@app.route('/api/reviews/<int:id>', methods=['DELETE'])
@login_required
def delete_review(id):
    review = Review.query.get_or_404(id)
    
    if not current_user.is_admin and review.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    db.session.delete(review)
    db.session.commit()
    
    return jsonify({'message': 'Review deleted successfully'}), 200

@app.route('/api/wishlist', methods=['GET'])
@login_required
def get_wishlist():
    wishlist_items = WishlistItem.query.filter_by(user_id=current_user.id).all()
    result = []
    
    for item in wishlist_items:
        product = item.product
        result.append({
            'id': item.id,
            'product_id': product.id,
            'name': product.name,
            'price': product.price,
            'image': product.image
        })
    
    return jsonify(result), 200

@app.route('/api/wishlist', methods=['POST'])
@login_required
def add_to_wishlist():
    data = request.get_json()
    
    existing_item = WishlistItem.query.filter_by(
        user_id=current_user.id,
        product_id=data['product_id']
    ).first()
    
    if existing_item:
        return jsonify({'message': 'Product already in wishlist'}), 200
    
    new_item = WishlistItem(
        user_id=current_user.id,
        product_id=data['product_id']
    )
    
    db.session.add(new_item)
    db.session.commit()
    
    return jsonify({
        'id': new_item.id,
        'message': 'Product added to wishlist'
    }), 201

@app.route('/api/wishlist/<int:id>', methods=['DELETE'])
@login_required
def remove_from_wishlist(id):
    item = WishlistItem.query.get_or_404(id)
    
    if item.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    db.session.delete(item)
    db.session.commit()
    
    return jsonify({'message': 'Product removed from wishlist'}), 200

@app.route('/api/repair', methods=['POST'])
def create_repair_request():
    data = request.get_json()
    
    new_request = RepairRequest(
        name=data['name'],
        email=data['email'],
        phone=data['phone'],
        device_type=data['device_type'],
        device_model=data['device_model'],
        problem=data['problem']
    )
    
    db.session.add(new_request)
    db.session.commit()
    
    return jsonify({
        'id': new_request.id,
        'message': 'Repair request submitted successfully'
    }), 201

@app.route('/api/repair', methods=['GET'])
@login_required
def get_repair_requests():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    requests = RepairRequest.query.all()
    result = []
    
    for request in requests:
        result.append({
            'id': request.id,
            'name': request.name,
            'email': request.email,
            'phone': request.phone,
            'device_type': request.device_type,
            'device_model': request.device_model,
            'problem': request.problem,
            'status': request.status,
            'created_at': request.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify(result), 200

@app.route('/api/repair/<int:id>/status', methods=['PUT'])
@login_required
def update_repair_status(id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    repair_request = RepairRequest.query.get_or_404(id)
    data = request.get_json()
    
    repair_request.status = data['status']
    db.session.commit()
    
    return jsonify({'message': 'Repair request status updated successfully'}), 200

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    total_users = User.query.count()
    total_products = Product.query.count()
    total_orders = Order.query.count()
    total_revenue = db.session.query(db.func.sum(Order.total)).scalar() or 0
    
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(5).all()
    recent_orders_data = []
    
    for order in recent_orders:
        recent_orders_data.append({
            'id': order.id,
            'user_name': order.user.name,
            'total': order.total,
            'status': order.status,
            'created_at': order.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    low_stock_products = Product.query.filter(Product.stock < 5).all()
    low_stock_data = []
    
    for product in low_stock_products:
        low_stock_data.append({
            'id': product.id,
            'name': product.name,
            'stock': product.stock
        })
    
    return jsonify({
        'total_users': total_users,
        'total_products': total_products,
        'total_orders': total_orders,
        'total_revenue': total_revenue,
        'recent_orders': recent_orders_data,
        'low_stock_products': low_stock_data
    }), 200

# Маршрути для статичних файлів
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

# Ініціалізація бази даних та створення адміністратора
@app.before_first_request
def initialize_database():
    db.create_all()
    
    # Створення адміністратора, якщо він не існує
    admin = User.query.filter_by(email='admin@lending.ua').first()
    if not admin:
        admin = User(
            email='admin@lending.ua',
            password=generate_password_hash('admin123'),
            name='Administrator',
            is_admin=True
        )
        db.session.add(admin)
        
        # Створення категорій
        categories = [
            Category(name='Мобільні аксесуари', slug='mobile-accessories'),
            Category(name='Б/У ноутбуки', slug='used-laptops'),
            Category(name='Б/У телефони', slug='used-phones')
        ]
        
        for category in categories:
            db.session.add(category)
        
        db.session.commit()
        
        # Створення тестових товарів
        products = [
            Product(
                name='Чохол для iPhone 13 силіконовий прозорий',
                description='Якісний силіконовий чохол для iPhone 13. Прозорий, не жовтіє з часом.',
                price=299,
                old_price=399,
                image='/images/products/case-iphone.jpg',
                stock=15,
                category_id=1
            ),
            Product(
                name='Бездротові навушники TWS з активним шумопоглинанням',
                description='Бездротові навушники з активним шумопоглинанням, Bluetooth 5.2, до 6 годин роботи.',
                price=1299,
                old_price=1599,
                image='/images/products/headphones.jpg',
                stock=8,
                category_id=1
            ),
            Product(
                name='Ноутбук Dell Latitude E7470 (б/у)',
                description='Intel Core i5-6300U, 8GB RAM, 256GB SSD, 14" Full HD, Windows 10 Pro.',
                price=8999,
                old_price=10999,
                image='/images/products/laptop-dell.jpg',
                stock=3,
                category_id=2
            ),
            Product(
                name='iPhone 11 64GB (б/у)',
                description='Стан 9/10, повний комплект, гарантія 3 місяці.',
                price=12999,
                old_price=14999,
                image='/images/products/iphone-11.jpg',
                stock=5,
                category_id=3
            )
        ]
        
        for product in products:
            db.session.add(product)
        
        db.session.commit()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
