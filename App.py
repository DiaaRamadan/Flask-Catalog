import requests
# Import from sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# import from Flask
from flask_oauth import OAuth
from flask import (Flask,
                   url_for,
                   request,
                   redirect,
                   render_template,
                   session as login_session,
                   abort,
                   flash,
                   g,
                   jsonify)

# Import from database.py
from database import Base, User, Category, Items

# import from psslib for hashed password
from passlib.apps import custom_app_context as pwd_context

# import from decorators
from decorators import login_required
from sqlalchemy.pool import StaticPool

app = Flask(__name__)
oauth = OAuth()
engine = create_engine('sqlite:///catalogdata.db',
                       connect_args={'check_same_thread': False},
                       poolclass=StaticPool, echo=True)
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Start route for main page
@app.route('/')
def index():
    categories = session.query(Category)
    return render_template('home.html', categories=categories, pagename='Home')


# Start route for main page
@app.route('/sign', methods=['POST', 'GET'])
def new_users():
    if 'logged_in' in login_session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if username is None or email is None or password is None:
            abort(400)
            print 'Missing arguments'
        if session.query(User).filter_by(username=username).first() is not None:
            flash('This user already found')
            return redirect(url_for('new_users'))

        if session.query(User).filter_by(email=email).first() is not None:
            flash('This email address already found')
            return redirect(url_for('new_users'))
        user = User(username=username, email=email)
        user.hash_password(password)
        session.add(user)
        session.commit()
        login_session['logged_in'] = True
        login_session['username'] = username
        flash('Sign up completed')
        return redirect(url_for('index'))
    else:
        return render_template('signForm.html', pagename='Sign up')


# Start route for log out
@app.route('/logout')
@login_required
def logout():
    login_session.pop('logged_in', None)
    login_session.pop('access_token', None)
    login_session.pop('username', None)
    return redirect(url_for('index'))


# Start route for login user
@app.route('/user_login', methods=['POST', 'GET'])
def user_login():
    if 'logged_in' in login_session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username is None or password is None:
            abort(400)
            print 'Missing arguments'
        if session.query(User).filter_by(username=username).first() is None:
            flash('This User not found')
            return redirect(url_for('user_login'))
        userInfo = session.query(User).filter_by(username=username).first()
        if userInfo > 0:
            if pwd_context.verify(password, userInfo.password):
                login_session['logged_in'] = True
                login_session['username'] = username
                return redirect(url_for('index'))
            flash('Invalid Password')
            return redirect('user_login')

    else:
        return render_template('loginForm.html', pagename='Log in')


# Start route for add category
@app.route('/category/new', methods=['POST', 'GET'])
@login_required
def create_category():
    if request.method == 'POST':
        name = request.form.get('catname')
        description = request.form['cat_desc']
        user_session = login_session['username']
        if name is None or description is None:
            print 'Missing arguments'
            abort(400)
        user_id = session.query(User).\
            filter_by(username=user_session).first()
        catInfo = Category(name=name, description=description, user_id=user_id.id)
        session.add(catInfo)
        session.commit()
        flash('Your category is added successfully')
        return redirect(url_for('index'))
    else:
        return render_template('newcat.html', pagename='Add New Category')


# Start route for Delete Category (only Admin)
@app.route('/category/<int:cat_id>/delete')
@login_required
def deleteCategory(cat_id):
    cat = session.query(Category).filter_by(id=cat_id).one()
    session.delete(cat)
    session.commit()
    flash('Your Category deleted successfully')
    return redirect(url_for('index'))


# Start route for add category
@app.route('/item/<int:cat_id>/new', methods=['POST', 'GET'])
@login_required
def create_item(cat_id):
    if request.method == 'POST':
        name = request.form['item_name']
        description = request.form['item_desc']
        price = request.form['item_price']
        user_session = login_session['username']
        if name is None or description is None or price is None:
            print 'Missing arguments'
            abort(400)
        user_id = session.query(User).\
            filter_by(username=user_session).first()
        item = Items(itemName=name, itemDesc=description, itemPrice=price, userID=user_id.id, catID=cat_id)
        session.add(item)
        session.commit()
        flash('Your item is added successfully')
        return redirect(url_for('showCategoryItems', cat_id=cat_id))
    else:
        return render_template('addItem.html', cat_id=cat_id, pagename='Add item')


# Start route for show the category items
@app.route('/category/<int:cat_id>/items')
@login_required
def showCategoryItems(cat_id):
    items = session.query(Items).\
        filter_by(catID=cat_id).all()
    category = session.query(Category).\
        filter_by(id=cat_id).first()
    user = session.query(User).filter_by(username=login_session['username']).first()
    return render_template('items.html', items=items, user=user, category=category, pagename='Items')


# Start route for edit item
@app.route('/item/<int:cat_id>/<int:item_id>/edit', methods=['POST', 'GET'])
@login_required
def editItem(cat_id, item_id):
    item = session.query(Items).filter_by(item_id=item_id).one()
    if request.method == 'POST':
        name = request.form['item_name']
        description = request.form['item_desc']
        price = request.form['item_price']
        item.itemName = name
        item.itemDesc = description
        item.itemPrice = price
        session.add(item)
        session.commit()
        flash('Your item is Edit successfully')
        return redirect(url_for('showCategoryItems', cat_id=cat_id))
    else:
        return render_template('editItem.html', cat_id=cat_id, item_id=item_id, item=item)


# route for delete item
@app.route('/item/<int:cat_id>/<int:item_id>/delete', methods=['POST', 'GET'])
@login_required
def deleteItem(cat_id, item_id):
    item = session.query(Items).\
        filter_by(item_id=item_id).one()
    session.delete(item)
    session.commit()
    flash('Your item deleted successfully')
    return redirect(url_for('showCategoryItems', cat_id=cat_id))


# Start route for show all items
@app.route('/all/items')
def showAllItems():
    allItems = session.query(Items).all()
    return render_template('allItems.html', allItems=allItems, pagename="All Items")


# Start item show data as jason(admin only)
@app.route('/items/jason')
@login_required
def itemJason():
    items = session.query(Items).all()
    return jsonify(Items=[item.serilize for item in items])


# Start categories show data as jason(admin only)
@app.route('/categories/jason')
@login_required
def CategoryJason():
    cats = session.query(Category).all()
    return jsonify(Categories=[cat.serilize for cat in cats])


# Start route for admin dashboard
@app.route('/admin/dashboard')
def adminDashboard():
    user_rows = session.query(User).count()
    item_rows = session.query(Items).count()
    cat_rows = session.query(Category).count()
    return render_template('admindashboard.html', user=user_rows, cats=cat_rows, items=item_rows, pagename='Dashboard')


# google login

# configure 3 values from Google APIs console
GOOGLE_CLIENT_ID = '458867031915-m0a0hkn0i4vqsc7uhepomkh01rudgvmp.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '6ca41ZRhpoMs-qOcY2hDJR1Z'
REDIRECT_URI = '/oauth2callback'
google = oauth.remote_app('google',
                          base_url='https://www.google.com/accounts/',
                          authorize_url='https://accounts.google.com/o/oauth2/auth',
                          request_token_url=None,
                          request_token_params={'scope': 'https://www.googleapis.com/auth/userinfo.email',
                                                'response_type': 'code'},
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          access_token_method='POST',
                          access_token_params={'grant_type': 'authorization_code'},
                          consumer_key=GOOGLE_CLIENT_ID,
                          consumer_secret=GOOGLE_CLIENT_SECRET)


@app.route('/gconnect')
def gconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        return redirect(url_for('glogin'))

    access_token = access_token[0]
    from urllib2 import Request, urlopen, URLError

    headers = {'Authorization': 'OAuth ' + access_token}
    req = Request('https://www.googleapis.com/oauth2/v1/userinfo',
                  None, headers)

    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()
    username= data['name']
    email = data['email']
    if session.query(User).\
            filter_by(username=username).first() is None:
        user = User(username=username, email=email)
        session.add(user)
        session.commit()
        login_session['access_token'] = access_token
        login_session['logged_in'] = True
        login_session['username'] = username
    else:
        login_session['access_token'] = access_token
        login_session['logged_in'] = True
        login_session['username'] = username
    try:
        res = urlopen(req)
    except URLError, e:
        if e.code == 401:
            # Unauthorized - bad token
            login_session.pop('access_token', None)
            return redirect(url_for('glogin'))

        return redirect(url_for('index'))

    return redirect(url_for('index'))


@app.route(REDIRECT_URI)
@google.authorized_handler
def authorized(resp):
    access_token = resp['access_token']
    login_session['access_token'] = access_token, ''
    return redirect(url_for('glogin'))


@google.tokengetter
def get_access_token():
    return login_session.get('access_token')


@app.route('/glogin')
def glogin():
    callback = url_for('authorized', _external=True)
    return google.authorize(callback=callback)



if __name__ == '__main__':
    app.secret_key = 'Super_secret_key'
    app.debug = True
    app.run(port=5000)
