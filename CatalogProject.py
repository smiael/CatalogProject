from flask import (Flask,
                    render_template,
                    request,
                    redirect,
                    jsonify,
                    url_for,
                    flash)
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
import datetime

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog App"

# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    req = h.request(url, 'GET')[1]
    req_json = req.decode('utf8').replace("'", '"')
    result = json.loads(req_json)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is \
                    already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px;' \
                'height: 300px;' \
                'border-radius: 150px;' \
                '-webkit-border-radius: 150px;' \
                '-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke \
                    token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Catalog Information
@app.route('/catalog.json')
def catalogsJSON():
    categorys = session.query(Category).all()
    return jsonify(categorys=[c.serialize for c in categorys])


# Show all categories
@app.route('/')
def showCategorys():
    items = session.query(Item).order_by(desc(Item.recent))
    categorys = session.query(Category).order_by(asc(Category.name))
    if 'username' not in login_session:
        return render_template('publiccategorys.html',
                                categorys=categorys,
                                items=items)
    else:
        return render_template('categorys.html',
                                categorys=categorys,
                                items=items)


@app.route('/catalog/<string:category>/items')
def showCategory(category):
    select_category = session.query(Category).filter_by(name=category).one()
    items = session.query(Item).filter_by(category_id=select_category.id)\
                .order_by(desc(Item.recent))
    categorys = session.query(Category).order_by(asc(Category.name))
    if 'username' not in login_session:
        return render_template('publiccategory.html',
                                categorys=categorys,
                                items=items,
                                select_category=select_category)
    else:
        return render_template('category.html',
                                categorys=categorys,
                                items=items,
                                select_category=select_category)


@app.route('/catalog/<string:category>/<item>')
def showItem(category, item):
    item = session.query(Item).filter_by(name=item).one()
    if 'username' not in login_session:
        return render_template('publicitem.html',
                                item=item)
    else:
        return render_template('item.html',
                                item=item)


# Create a new item
@app.route('/item/new/', methods=['GET', 'POST'])
def newItem():
    if 'username' not in login_session:
        return redirect('/login')
    categorys = session.query(Category).order_by(asc(Category.name))
    if request.method == 'POST':
        updated = datetime.date.today()
        newItem = Item(
            name=request.form['name'],
            description=request.form['description'],
            category_id=request.form['category'],
            user_id=login_session['user_id'],
            recent=updated)
        session.add(newItem)
        flash('New Item %s Successfully Created' % newItem.name)
        session.commit()
        return redirect(url_for('showCategorys'))
    else:
        return render_template('newitem.html',
                                categorys=categorys)

# Edit an item


@app.route('/catalog/<string:item>/edit', methods=['GET', 'POST'])
def editItem(item):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Item).filter_by(name=item).one()
    categorys = session.query(Category).order_by(asc(Category.name))
    if editedItem.user_id != login_session['user_id']:
        return "<script>function myFunction() \
                {alert('You are not authorized to edit this item. \
                Please create your own item in order to edit.'); \
                window.location = '/item/new/';}\
                </script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['category']:
            editedItem.category_id = request.form['category']
        session.add(editedItem)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('showCategorys'))
    else:
        return render_template('edititem.html',
                                categorys=categorys,
                                item=editedItem,
                                category_id=editedItem.category_id)


# Delete an item
@app.route('/catalog/<string:item>/delete', methods=['GET', 'POST'])
def deleteItem(item):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(Item).filter_by(name=item).one()
    if itemToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() \
                {alert('You are not authorized to delete this item. \
                Please create your own item in order to delete.');\
                window.location = '/';}\
                </script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showCategorys'))
    else:
        return render_template('deleteItem.html',
                                item=itemToDelete)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCategorys'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCategorys'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
