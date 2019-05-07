from flask import render_template,request, redirect, url_for,flash,session
from models import app, db, User, Discussion, Message
from datetime import datetime
from utils import password_check

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

#just comment

@app.route('/')
def index():
  discussions = Discussion.query.all()
  return render_template('index.html', discussions=discussions)


@app.route('/messages/<int:discussion_id>/',methods = ['GET', 'POST'])
def messages(discussion_id):
    if 'username' in session:
        if request.method == 'POST':
            text = request.form['message']
            user = User.query.filter_by(username=session['username']).first()
            u = Message(text=text,discussion_id=discussion_id,user_id=user.id)
            db.session.add(u)
            db.session.commit()
    messages = Message.query.filter_by(discussion_id=discussion_id).order_by(Message.date.desc()).all()
    discussion = Discussion.query.filter_by(id=discussion_id).first()
    for message in messages:
       message.user = User.query.filter_by(id=message.user_id).first()
    return render_template('messages.html',messages=messages,discussion=discussion)


@app.route('/signup',methods = ['GET', 'POST'])
def signup():
    if 'username' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first() == None:
            if password_check(password):
                user = User(username=username,password=password)
                flash('User saved succefuly')
                db.session.add(user)
                db.session.commit()
                session['username'] = username
                return redirect(url_for('index'))
            else:
                flash(' password is too weak')
        else:
            flash('Username already exist')
    return render_template('signup.html')



@app.route('/login',methods = ['GET', 'POST'])
def login():
    if 'chances' not in session:
        session['chances'] = 3 
    if 'username' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        if session['chances'] < 1 : 
            flash('Too many login attemps')
        else:
            user = User.query.filter_by(
                username=request.form['username'],
                password=request.form['password']
            ).first()
            if user:
                session['username'] = request.form['username']
                return redirect(url_for('index'))
            else:
                session['chances'] -= 1 
                flash('Invalid credentials you have {} chances remaining'.format(session['chances']))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username')
    return redirect(url_for('index'))


@app.route('/profile/<int:user_id>/',methods = ['GET', 'POST'])
def profile(user_id):
    user = User.query.filter_by(id=user_id).first()
    messages = Message.query.filter_by(user_id=user_id).order_by(Message.date.desc()).all()
                
    return render_template('profile.html',user=user,messages=messages)

@app.route('/change_password/<int:user_id>/',methods = ['GET', 'POST'])
def change_password(user_id):
    user = User.query.filter_by(id=user_id).first()
    if 'username' in session and session['username'] == user.username :
        if request.method == 'POST':
            old_password = request.form['old_password']
            new_password = request.form['new_password']
            user = User.query.filter_by(
                    username=session['username'],
                    password=old_password
                ).first()
            if user != None:
                    if password_check(new_password) and new_password != old_password:
                        user.password = new_password
                        flash('Password change with succes')
                        db.session.commit()
                    else:
                        flash('new password is too weak')
            return redirect(request.path,code=302)
    return redirect(url_for('profile',user_id=user.id))

@app.route('/change_username/<int:user_id>/',methods = ['GET', 'POST'])
def change_username(user_id):
    user = User.query.filter_by(id=user_id).first()
    if 'username' in session and session['username'] == user.username :
        if request.method == 'POST':
            new_username = request.form['new_username']
            shearched_user = User.query.filter_by(username=new_username).first()
            if shearched_user == None:
                user.username = new_username
                flash('Username change with succes')
                db.session.commit()
                session['username'] = new_username
            return redirect(request.path,code=302)
    return redirect(url_for('profile',user_id=user.id))








