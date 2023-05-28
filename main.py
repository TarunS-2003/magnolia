import os
from flask import Flask, render_template, url_for, redirect, request, jsonify
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
app.config['SECRET_KEY'] = 'abcd'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
metadata = MetaData()


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


@app.route('/dashboard')
@login_required
def dashboard():
    table_name = current_user.username.replace(' ', '_').lower()
    table_name = ''.join(c for c in table_name if c.isalnum())  # Remove special characters from table name

    engine = db.get_engine()
    inspector = db.inspect(engine)

    if inspector.has_table(table_name):
        table = Table(table_name, metadata, autoload=True, autoload_with=engine)
        query = select([table])
        items = db.engine.execute(query)
        return render_template('dashboard.html', items=items)

    return render_template('dashboard.html', items=None)


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
            item = table.insert().values(name=name, quantity=quantity, price=price)
            db.engine.execute(item)

        return redirect(url_for('dashboard'))

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


@app.route('/analysis')

@login_required

def analysis():
    table_name = current_user.username.replace(' ', '_').lower()
    table_name = ''.join(c for c in table_name if c.isalnum())  # Remove special characters from table name

    engine = db.get_engine()
    inspector = db.inspect(engine)

    if inspector.has_table(table_name):
        table = Table(table_name, metadata, autoload=True, autoload_with=engine)
        query = select([table.c.name, table.c.quantity])
        result = db.engine.execute(query)

        products = []
        quantities = []

        for row in result:
            products.append(row[0])
            quantities.append(row[1])

        # Create bar plot
        x_pos = np.arange(len(products))
        plt.bar(x_pos, quantities, align='center')
        plt.xticks(x_pos, products)
        plt.xlabel('Product')
        plt.ylabel('Quantity')
        plt.title('Quantity of Products')

        # Save the plot to a file
        plt.savefig('static/graph.png')

        return render_template('analysis.html')
    else:
        return render_template('analysis.html', error='No data available for analysis')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
