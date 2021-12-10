from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from sqlalchemy import select
from sqlalchemy.orm import backref, relationship, session
from sqlalchemy.sql.expression import false
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from wtforms.widgets.core import Select

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    __tablename__ = 'User'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


class Players(db.Model):
    __tablename__ = 'Players'

    id = db.Column(db.Integer, primary_key =True)
    player_name = db.Column(db.String(30), unique=True)
    team_id = db.Column(db.Integer, db.ForeignKey('Team.id'), nullable=false)

class Team(db.Model):
    __tablename__ = 'Team'

    id = db.Column(db.Integer, primary_key=True)
    team_name = db.Column(db.String(30), unique=True)
    #players = db.relationship('Players', backref='team', lazy=True)
#db.drop_all()
db.create_all()
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class TeamForm(FlaskForm):
    team_name = StringField('Team Name',validators=[InputRequired()])
    submit = SubmitField('Add Team')

class PlayerForm(FlaskForm):
    player_name = StringField('Player Name',validators=[InputRequired()])
    team_query = Team.query.all()
    team = []
    for t in team_query:
        team.append(t.team_name)
    team_name = SelectField('Teams', choices=team)
    submit = SubmitField('Add Player')


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'
    return render_template('login.html', form=form)

@app.route("/home")
def returntohome():
    return redirect(url_for('index'))



@app.route('/add/teams', methods=['GET', 'POST'])
def addteam():
    message = ""
    form = TeamForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            team =  Team.query.filter_by(team_name=form.team_name.data).first()
            if team:
                message = f'Error, {form.team_name._value()} has already been added'
            else:
                team_name = Team(team_name=form.team_name.data)
                db.session.add(team_name)
                db.session.commit()
                message = f'Thank you, {form.team_name._value()} has been added'
    return render_template('addteams.html', form=form, message=message)

@app.route('/view/teams')   
def viewteams():
    all_teams = Team.query.all()
    team_string = ""
    for team in all_teams:
        team_string +=  team.team_name + "<br>"
    return team_string

@app.route('/add/players', methods=['GET', 'POST'])
def addplayers():
    message = ""
    form = PlayerForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            player =  Players.query.filter_by(player_name=form.player_name.data).first()
            if player:
                message = f'Error, {form.player_name._value()} has already been added'
            else:
                team_id = Team.query.filter_by(team_name=form.team_name.data).first().id
                player_name = Players(player_name=form.player_name.data, team_id=team_id)
                db.session.add(player_name)
                db.session.commit()
                message = f'Thank you, {form.player_name._value()} has been added'
    return render_template('addplayers.html', form=form, message=message)

@app.route('/view/<teams>/players')
def displayplayers(teams):
    player_string = ""
    team_id = Team.query.filter(Team.team_name==str(teams)).first().id
    all_players = db.session.query(Players.player_name).filter(Players.team_id == team_id).all()
    for player in all_players:
        player_string +=  player.player_name + "<br>"
    return player_string

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'

    return render_template('signup.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')