import os
from flask import Flask, render_template, url_for, redirect, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select, MetaData, Table, Column, Integer, String
from flask_login import UserMixin, LoginManager, login_user, current_user, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np


app = Flask(__name__, static_url_path='/static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = os.environ['DB_SECRET_KEY']
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
metadata = MetaData()
app.secret_key = 'abcd'
temporary = ""

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False, unique=True)


class SignupForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=25)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Submit")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    flag = False
    form = LoginForm()

    if form.validate_on_submit():
        global user_name
        user_name = form.username.data
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            session['user_name'] = user.username
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
        else:
            return jsonify({'error': 'Invalid Username'})

    return render_template("login.html", form=form, flag=flag)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        session['user_name'] = form.username.data
        username = form.username.data
        table_name = username.replace(' ', '_').lower()
        table_name = ''.join(c for c in table_name if c.isalnum())  # Remove special characters from table name

        engine = db.get_engine()
        inspector = db.inspect(engine)

        if not inspector.has_table(table_name):
            table = Table(
                table_name,
                metadata,
                Column('id', Integer, primary_key=True),
                Column('name', String(100), nullable=False),
                Column('quantity', Integer, nullable=False),
                Column('price', Integer, nullable=False),
            )
            table.create(engine)

        return redirect(url_for('login'))

    return render_template("signup.html", form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    table_name = current_user.username.replace(' ', '_').lower()
    table_name = ''.join(c for c in table_name if c.isalnum())  # Remove special characters from table name

    engine = db.get_engine()
    inspector = db.inspect(engine)

    if inspector.has_table(table_name):
        table = Table(table_name, metadata, autoload=True, autoload_with=engine)
        query = select([table])
        result = db.engine.execute(query)

        items = []

        for row in result:
            item = {
                'id': row['id'],
                'name': row['name'],
                'quantity': row['quantity'],
                'price': row['price']
            }
            items.append(item)

        if request.method == 'POST':
            item_id = int(request.form['item_id'])
            action = request.form['action']  # increment or decrement

            item = table.select().where(table.c.id == item_id).execute().fetchone()

            if item:
                current_quantity = item['quantity']

                if action == 'increment':
                    new_quantity = current_quantity + 1
                elif action == 'decrement':
                    new_quantity = max(current_quantity - 1, 0)

                # Update the quantity in the database
                update_query = table.update().where(table.c.id == item_id).values(quantity=new_quantity)
                db.engine.execute(update_query)

        return render_template('dashboard.html', items=items)
    else:
        return render_template('dashboard.html', error='No data available')

@app.route('/increment', methods=['POST'])
@login_required
def increment():
    item_id = int(request.form['item_id'])
    user_name = session.get('user_name')
    table_name = user_name.replace(' ', '_').lower()
    table_name = ''.join(c for c in table_name if c.isalnum())  # Remove special characters from table name

    engine = db.get_engine()
    inspector = db.inspect(engine)

    if inspector.has_table(table_name):
        table = Table(table_name, metadata, autoload=True, autoload_with=engine)
        item = table.select().where(table.c.id == item_id)

        with engine.begin() as conn:
            result = conn.execute(item).fetchone()

            if result is None:
                return jsonify({'error': 'Product not found'})

            current_quantity = result['quantity']
            new_quantity = current_quantity + 1

            update_query = table.update().where(table.c.id == item_id).values(quantity=new_quantity)
            conn.execute(update_query)

        return redirect(url_for('dashboard'))

    return jsonify({'error': 'Table not found'})


@app.route('/decrement', methods=['POST'])
@login_required
def decrement():
    item_id = int(request.form['item_id'])
    user_name = session['user_name']
    table_name = user_name.replace(' ', '_').lower()
    table_name = ''.join(c for c in table_name if c.isalnum())  # Remove special characters from table name

    engine = db.get_engine()
    inspector = db.inspect(engine)

    if inspector.has_table(table_name):
        table = Table(table_name, metadata, autoload=True, autoload_with=engine)
        item = table.select().where(table.c.id == item_id)

        with engine.begin() as conn:
            result = conn.execute(item).fetchone()

            if result is None:
                return jsonify({'error': 'Product not found'})

            current_quantity = result['quantity']
            new_quantity = max(current_quantity - 1, 0)

            update_query = table.update().where(table.c.id == item_id).values(quantity=new_quantity)
            conn.execute(update_query)

        return redirect(url_for('dashboard'))

    return jsonify({'error': 'Table not found'})

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == 'POST':
        name = request.form['name']
        quantity = int(request.form['quantity'])
        price = float(request.form['price'])

        table_name = current_user.username.replace(' ', '_').lower()
        table_name = ''.join(c for c in table_name if c.isalnum())  # Remove special characters from table name

        engine = db.get_engine()
        inspector = db.inspect(engine)

        if inspector.has_table(table_name):
            table = Table(table_name, metadata, autoload=True, autoload_with=engine)
            insert_query = table.insert().values(name=name, quantity=quantity, price=price)
            db.engine.execute(insert_query)
            return redirect(url_for('dashboard'))
        else:
            return render_template('add.html', error='No data available')

    return render_template('add.html')

@app.route('/drop/<int:item_id>', methods=['POST'])
@login_required
def drop(item_id):
    table_name = current_user.username.replace(' ', '_').lower()
    table_name = ''.join(c for c in table_name if c.isalnum())  # Remove special characters from table name

    engine = db.get_engine()
    inspector = db.inspect(engine)

    if inspector.has_table(table_name):
        table = Table(table_name, metadata, autoload=True, autoload_with=engine)
        item = table.delete().where(table.c.id == item_id)
        db.engine.execute(item)

    return redirect(url_for('dashboard'))

@app.route('/analysis', methods=['GET', 'POST'])
@login_required
def analysis():
    table_name = current_user.username.replace(' ', '_').lower()
    table_name = ''.join(c for c in table_name if c.isalnum())  # Remove special characters from table name

    engine = db.get_engine()
    inspector = db.inspect(engine)

    if inspector.has_table(table_name):
        table = Table(table_name, metadata, autoload=True, autoload_with=engine)
        query = select([table])
        result = db.engine.execute(query)

        items = []

        for row in result:
            item = {
                'name': row['name'],
                'quantity': row['quantity'],
                'price': row['price']
            }
            items.append(item)

        if len(items) > 0:
            labels = [item['name'] for item in items]
            quantities = [item['quantity'] for item in items]
            if os.path.exists('static/graph.png'):
              os.remove('static/graph.png')
            plt.figure(figsize=(10, 6))
            plt.bar(labels, quantities)
            plt.xlabel('Item')
            plt.ylabel('Quantity')
            plt.title('Inventory Chart')
            plt.xticks(rotation=45)
            plt.tight_layout()

            
            plt.savefig('static/graph.png')

            return render_template('analysis.html')
        else:
            return render_template('analysis.html', error='No data available')

    else:
        return render_template('analysis.html', error='No data available')


if __name__ == '__main__':
    app.run(debug=True,host = '0.0.0.0')
