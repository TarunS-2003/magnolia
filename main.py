from flask import Flask,render_template,url_for,redirect,request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,LoginManager,login_user,current_user,login_required,logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt


app = Flask(__name__,static_url_path = '/static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database2.db'
app.config['SECRET_KEY'] = 'th-is-a-s3cr3t-key#'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader

def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model,UserMixin):
  id = db.Column(db.Integer,primary_key = True)
  username = db.Column(db.String(25),nullable = False,unique = True)
  password = db.Column(db.String(80),nullable = False,unique = True)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return f"Item('{self.name}', {self.quantity}, {self.price})"

class SignupForm(FlaskForm):
  username = StringField(validators = [InputRequired(), Length(min = 4,max = 20)], render_kw={"placeholder":"Username"})
  password = PasswordField(validators = [InputRequired(), Length(min = 4, max = 25)],render_kw = {"placeholder":"Password"})
  submit = SubmitField("Submit")

  def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
    
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


with app.app_context():
  db.create_all()


@app.route("/")

def home():
  return render_template("home.html")

@app.route("/login",methods = ["GET","POST"])

def login():
  flag = False
  form = LoginForm()
  
  if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
              
        else:
          flag = True
          
  return render_template("login.html",form = form,flag = flag)

@app.route("/singup",methods = ["GET","POST"])

def signup():
  form = SignupForm()
  
  if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
  return render_template("signup.html",form = form)

@app.route('/logout', methods=['GET', 'POST'])

@login_required

def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')

def dashboard():
    items = Item.query.all()
    return render_template('dashboard.html', items=items)

@app.route('/add', methods = ['GET','POST'])

@login_required

def add():
    if request.method == 'POST':
        name = request.form['name']
        quantity = int(request.form['quantity'])
        price = float(request.form['price'])

        item = Item(name=name, quantity=quantity, price=price)
        db.session.add(item)
        db.session.commit()
        return redirect(url_for('dashboard'))
    
    return render_template('add.html')


@app.route('/drop/<int:item_id>', methods=['POST'])

@login_required

def drop(item_id):
    item = Item.query.get(item_id)
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('dashboard'))

#version1
if __name__ == '__main__':
  app.run(debug = True,host = '0.0.0.0')
