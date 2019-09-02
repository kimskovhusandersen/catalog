#!/usr/bin/python3
from flask_sslify import SSLify
from models import (Base, User, Category, Item, association, ItemSerializer,
                    CategorySerializer)
from flask import (Flask, jsonify, request, url_for, render_template, flash,
                   redirect, make_response, session as login_session, abort, g)
from sqlalchemy import create_engine, func
from sqlalchemy.orm import scoped_session, sessionmaker
import json
from collections import OrderedDict
import random
import string
import httplib2
import requests
import os as os
import time
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask_httpauth import HTTPBasicAuth
from functools import update_wrapper
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# from OpenSSL import SSL
auth = HTTPBasicAuth()

"""
context = SSL.Context(SSL.SSLv23_METHOD)
context.use_privatekey_file('server.key')
context.use_certificate_file('server.crt')
"""

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
session = scoped_session(sessionmaker(bind=engine))


app = Flask(__name__)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["2000 per day", "500 per hour"]
)

"""
context = ('web.crt', 'web.key')
sslify = SSLify(app)
"""

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog"
APIDOCS = json.loads(
    open('static/Project Catalog API.json', 'r').read())


# READ Login
@app.route('/login')
def showLogin():
    state = ''.join(
        random.choice(
            string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


"""
@app.route('/clientOAuth')
def clientOAuth():
    return render_template('clientOAuth.html')
"""

# category routes
# CREATE CATEGORY
@app.route('/catalog/new/', methods=['GET', 'POST'])
def newCategory():
    if request.method == "GET":
        if 'access_token' not in login_session:
            return redirect('/login')
        else:
            cancel = login_session.get('last_visited')[-1]
            return render_template('newcategory.html', cancel=cancel)

    if request.method == "POST":
        data = request.form
        create(Category, data)
        return redirect(url_for('showCatalog'))


# READ CATEGORIES
@app.route('/', methods=['GET'])
@app.route('/catalog/', methods=['GET'])
def showCatalog():
    categories = get_all(Category)
    try:
        latest = session.query(Item).filter(
            association.c.category_id == Category.id).filter(
            association.c.item_id == Item.id).order_by(
            Item.id.desc()).limit(10)
    except:
        pass
    if 'access_token' not in login_session:
        return render_template('publicindex.html', categories=categories,
                               latest=latest)
    else:
        return render_template('index.html', categories=categories,
                               latest=latest)

# UPDATE CATEGORY
@app.route('/catalog/<category>/edit/', methods=["GET", "POST"])
def editCategory(category):
    if request.method == "GET":
        if 'access_token' not in login_session:
            return redirect('/login')
        else:
            cancel = login_session.get('last_visited')[-1]
            category = get_first(Category, {"slug": category})
            if category is not None:
                return render_template('editCategory.html', category=category,
                                       cancel=cancel)

    if request.method == "POST":
        data = request.form
        row = update(Category, data, {"slug": category})
        if hasattr(row, 'id'):
            flash("Successfully updated category ID {}!".format(row.id))
            return redirect(url_for('showItems', category=row.slug))
        else:
            flash("Could not update this category {}!".format(
                row.response[0]))
            return redirect(url_for('showItems', category=category))


# DELETE CATEGORY
@app.route('/catalog/<category>/delete/', methods=["GET", "POST"])
def deleteCategory(category):
    if request.method == "GET":
        if 'access_token' not in login_session:
            return redirect('/login')
        else:
            cancel = login_session.get('last_visited')[-1]
            row = get_first(Category, {"slug": category})
            return render_template('deleteCategory.html', category=row,
                                   cancel=cancel)

    if request.method == "POST":
        row = delete(Category, {"slug": category})
        if hasattr(row, 'id'):
            flash("Successfully deleted category ID {}!".format(row.id))
        else:
            flash("Could not delete this category {}!".format(
                row.response[0]))
        return redirect(url_for('showCatalog'))


# CREATE ITEM
@app.route('/catalog/<category>/create/', methods=['GET', 'POST'])
def newItem(category):
    if request.method == "GET":
        if 'access_token' not in login_session:
            return redirect('/login')
        else:
            cancel = login_session.get('last_visited')[-1]
            category = get_first(Category, {"slug": category})
            categories = get_all(Category)
            count = count_cat(Category)
            return render_template('newitem.html', categories=categories,
                                   category=category, count=count,
                                   cancel=cancel)

    if request.method == "POST":
        data = request.form
        item = create(Item, data)
        if hasattr(item, 'id'):
            flash("Successfully created Item ID {}!".format(item.id))
        return redirect(url_for('showItems', category=category))


# READ ITEMS
@app.route('/catalog/<category>/', methods=['GET'])
@app.route('/catalog/<category>/items', methods=['GET'])
def showItems(category):
    categories = get_all(Category)
    category = get_first(Category, {"slug": category})
    count = count_items(category.id)
    if 'access_token' not in login_session or \
            category.user_id != login_session['user_id']:
        return render_template('publiccategory.html',
                               categories=categories, category=category,
                               count=count)
    else:
        return render_template('category.html', categories=categories,
                               category=category, count=count)

# READ ITEM
@app.route('/catalog/<category>/<item>/', methods=['GET'])
def showItem(category, item):
    # category = get_first(Category, {"slug": category})
    item = get_first(Item, {"slug": item})
    if 'access_token' not in login_session or \
            item.user_id != login_session['user_id']:
        return render_template('publicitem.html', category=category, item=item)
    else:
        return render_template('item.html', category=category, item=item)


# UPDATE ITEM
@app.route('/catalog/<category>/<item>/edit/', methods=['GET', 'POST'])
def editItem(category, item):
    if request.method == "GET":
        if 'access_token' not in login_session:
            return redirect('/login')
        else:
            cancel = login_session.get('last_visited')[-1]
            categories = get_all(Category)
            count = count_cat(Category)
            item = get_first(Item, {"slug": item})
            return render_template('edititem.html', category=category,
                                   categories=categories, count=count,
                                   item=item, cancel=cancel)

    if request.method == "POST":
        data = request.form
        row = update(Item, data, {"slug": item})
        if hasattr(row, 'id'):
            flash("Successfully updated item ID {}!".format(row.id))
            return redirect(url_for(
                'showItem', category=category, item=row.slug))
        else:
            flash("Could not update this category {}!".format(
                row.response[0]))
            return redirect(url_for('showItem', category=category, item=item))


# DELETE ITEM
@app.route('/catalog/<category>/<item>/delete/', methods=['GET', 'POST'])
def deleteItem(category, item):
    if request.method == "GET":
        if 'access_token' not in login_session:
            return redirect('/login')
        else:
            cancel = login_session.get('last_visited')[-1]
            item = get_first(Item, {"slug": item})
            return render_template(
                'deleteitem.html', item=item, category=category, cancel=cancel)

    if request.method == "POST":
        row = delete(Item, {"slug": item})
        if hasattr(row, 'id'):
            flash("Successfully deleted item ID {}!".format(row.id))
        else:
            flash("Could not delete this item {}!".format(
                row.response[0]))
        return redirect(url_for('showItems', category=category))


@app.route('/API/', methods=['GET'])
def showAPI():
    api = json.dumps(APIDOCS, sort_keys=True, indent=4)
    loaded_api = json.loads(api)
    return render_template('API.html', api=loaded_api)


@app.route('/search/<search>', methods=['GET'])
def showSearch(search):
    if request.method == "GET":
        data = prepareData()
        title = data['search']
        item = get_first(Item, {"name": title})
        category = get_first(Category, {"name": title})
        wiki_item = getWikiInfo(title)
        wiki_categories = getWikiCategories(title)
        categories_exist = []
        if wiki_categories is not None:
            categories_exist = session.query(Category).filter(
                Category.name.in_(wiki_categories)).all()
            if categories_exist:
                filtered_wiki_categories = []
                for c in wiki_categories:
                    unique = True
                    for category in categories_exist:
                        if c == category.name:
                            unique = False
                            break
                    if unique is True:
                        filtered_wiki_categories.append(c)
                if filtered_wiki_categories != []:
                    wiki_categories = filtered_wiki_categories
        if 'access_token' not in login_session:
            return render_template('publicsearch.html', item=item,
                                   category=category, wiki_item=wiki_item,
                                   wiki_categories=wiki_categories,
                                   categories_exist=categories_exist)
        else:
            return render_template('search.html', item=item,
                                   category=category, wiki_item=wiki_item,
                                   wiki_categories=wiki_categories,
                                   categories_exist=categories_exist)

# ++++++++++
# API ROUTES:
# ++++++++++

# API CREATE CATEGORY
@app.route('/api/catalog', methods=['POST'])
@auth.login_required
def newCategoryAPI():
    data = prepareData()
    row = create(Category, data)
    data, errors = CategorySerializer.dump(row)
    if errors:
        return jsonify({"errors": errors})
    return jsonify({"Category": data})


# API READ CATEGORIES
@app.route('/api/catalog', methods=['GET'])
@limiter.limit("240 per day")
def showCatalogAPI():
    categories = get_all(Category)
    data = CategorySerializer.dump(categories, many=True)
    return jsonify({"Categories": data})


# API READ CATEGORY
@app.route('/api/catalog/<category_id>', methods=['GET'])
@limiter.limit("240 per day")
def showCategoryAPI(category_id):
    category = get_first(Category, {"id": category_id})
    if category is None:
        return "Need a valid category ID"
    data = CategorySerializer.dump(category)
    return jsonify({"Category": data})


# API UPDATE CATEGORY
@app.route('/api/catalog/<category_id>', methods=['PUT'])
@auth.login_required
def editCategoryAPI(category_id):
    data = prepareData()
    row = update(Category, data, {"id": category_id})
    data = CategorySerializer.dump(row)
    return jsonify({"Category": data})


# API DELETE CATEGORY
@app.route('/api/catalog/<category_id>', methods=['DELETE'])
@auth.login_required
def deleteCategoryAPI(category_id):
    row = delete(Category, {"id": category_id})
    if row is not None:
        return "Category ID {} successfully deleted".format(row.id)
    else:
        return jsonify({"message": "Could not find any category with that ID"})

# API CREATE ITEM
@app.route('/api/catalog/items', methods=['POST'])
@auth.login_required
def newItemAPI():
    data = prepareData()
    errors = []
    if 'name' not in data or data['name'] is None:
        errors.append("Need a valid name")
    if 'description' not in data or data['description'] is None:
        errors.append("Need a valid description")
    if 'categories' not in data or data['categories'] is None:
        errors.append("Need a valid array of category IDs")
    if errors != []:
        return jsonify({"message": errors})
    row = create(Item, data)
    data = ItemSerializer.dump(row)
    return jsonify({"Item": data})


# API READ ITEMS
@app.route('/api/catalog/items', methods=['GET'])
@limiter.limit("240 per day")
def showAllItemsAPI():
    items = get_all(Item)
    data = ItemSerializer.dump(items, many=True)
    return jsonify({"Items": data})


# API READ ITEM
@app.route('/api/catalog/items/<item_id>', methods=['GET'])
@limiter.limit("240 per day")
def showItemAPI(item_id):
    item = get_first(Item, {"id": item_id})
    data = ItemSerializer.dump(item)
    return jsonify({"Item": data})


# API READ ITEMS
@app.route('/api/catalog/<category_id>/items', methods=['GET'])
@limiter.limit("240 per day")
def showItemsAPI(category_id):
    items = session.query(Item).filter(
        association.c.category_id == category_id).filter(
        association.c.item_id == Item.id).all()
    data = CategorySerializer.dump(items, many=True)
    return jsonify({"Items": data})


# API READ ITEM
@app.route('/api/catalog/<category_id>/<item_id>', methods=['GET'])
@limiter.limit("240 per day")
def showItemByCategoryAPI(category_id, item_id):
    item = session.query(Item).filter(
        association.c.category_id == category_id).filter(
        association.c.item_id == Item.id).filter(Item.id == item_id).first()
    data = ItemSerializer.dump(item)
    return jsonify({"item": data})


# API UPDATE ITEM
@app.route('/api/catalog/items/<item_id>', methods=['PUT'])
@auth.login_required
def editItemAPI(item_id):
    data = prepareData()
    row = update(Item, data, {"id": item_id})
    data = ItemSerializer.dump(row)
    return jsonify({"Item": data})


# API DELETE ITEM
@app.route('/api/catalog/items/<item_id>', methods=['DELETE'])
@auth.login_required
def deleteItemAPI(item_id):
    row = delete(Item, {"id": item_id})
    if row is not None:
        return "Item ID {} successfully deleted".format(row.id)
    else:
        return jsonify({"message": "Could not find any item with that ID"})


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/api/oauth/<provider>', methods=['POST'])
def login(provider):
    # STEP 1 - Parse the auth code
    data = prepareData()
    if 'authorization_code' not in data or data['authorization_code'] is None:
        return jsonify({'message': "Need valid authorization code"})
    else:
        auth_code = data['authorization_code']

    if provider == 'google':
        # STEP 2 - Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets(
                'client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(json.dumps(
                'Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Check that the access token is valid.
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
               % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'

        # STEP 3 - Find User or make a new one
        # Get user info
        h = httplib2.Http()
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)
        data = answer.json()

        errors = []
        if 'name' not in data and data['name'] is None:
            errors.append("Need valid name")
        else:
            name = data['name']
        if 'picture' not in data and data['picture'] is None:
            errors.append("Need valid picture")
        else:
            picture = data['picture']
        if 'email' not in data and data['email'] is None:
            errors.append("Need valid email")
        else:
            email = data['email']
        if errors != []:
            return jsonify({"message": errors})

        # see if user exists, if it doesn't make a new one
        user = get_first(User, {"email": email})
        if user is None:
            user = User(name=name, picture=picture, email=email)
            session.add(user)
            session.commit()

        # STEP 4 - Make token
        token = user.generate_auth_token(600)

        # STEP 5 - Send back token to the client
        return jsonify({'token': token.decode('ascii')})

    else:
        return jsonify({"message": 'Unrecoginized Provider'})


@app.route('/api/users', methods=['POST'])
def new_user():
    message = []
    data = prepareData()

    if 'email' not in data or data['email'] is None:
        message.append("Need a valid email")
    else:
        email = data['email']
    if 'name' not in data or data['name'] is None:
        message.append("Need a valid name")
    else:
        name = data['name']
    if 'password' not in data or data['password'] is None:
        message.append("Need a valid password")
    else:
        password = data['password']
    if message != []:
        return jsonify({'message': message})

    exists = get_first(User, {"email": email})
    if exists is not None:
        return jsonify({'message': 'Email already exists'}), 200

    user = User()
    user.email = email
    user.name = name
    user.hash_password(password)
    try:
        session.add(user)
        session.commit()
        return jsonify({'email': user.email}), 201
    except:
        pass


@app.route('/api/users/<int:id>')
@auth.login_required
@limiter.limit("240 per day")
def get_user(id):
    user = get_first(User, {"id": id})
    if not user:
        return jsonify({'message': 'No user found with ID {}'.format(id)}), 200
    return jsonify({'email': user.email})


def prepareData():
    data = None
    if request.form:
        return request.form
    if request.args:
        return request.args
    elif request.get_json():
        return request.get_json()
    if not data or data is None:
        return jsonify({"message": "Could not retrieve data"})


# CREATE
def create(table, data):
    if 'user_id' in login_session:
        user_id = login_session['user_id']
        if not user_id:
            return make_response(jsonify({
                "message": "Need a valid user id"}), 401)
    if 'name' in data:
        name = data['name'].strip().lower().capitalize()
        if name == "":
            return make_response(jsonify(
                {"message": "Need a valid name"}), 400)
    exist = session.query(table).filter(
        table.name == name).first()
    if exist is not None:
        return make_response(jsonify(
            {"message": "That name has already been taken"}), 400)
    if table == Item:
        if 'description' in data:
            description = data['description']
        else:
            return make_response(jsonify(
                {"message": "Need valid description"}), 400)
        if 'categories' in data:
            if isinstance(data['categories'], list):
                categories = data['categories']
            else:
                categories = data.getlist('categories')
        if categories == [] or not isinstance(categories, list):
            return make_response(jsonify(
                {"message": "Need valid category ID(s) as array"}), 400)
    try:
        if table == Category:
            row = Category()
        if table == Item:
            row = Item()
            row.description = description
            exist = session.query(Category).filter(
                Category.id.in_(categories)).all()
            if exist:
                row.categories = []
                row.categories.extend(exist)
        row.name = name
        row.user_id = user_id
        session.add(row)
        session.commit()
        row = get_first(table, {"name": name})
        return row

    except:
        pass


def createUser(login_session):
    newUser = User(
        name=login_session['name'],
        email=login_session['email'],
        picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = get_first(User, {"email": login_session['email']})
    if user is not None:
        return user.id
    else:
        return None


# READ
def get_all(table):
    try:
        return session.query(table).order_by(table.name.asc()).all()
    except:
        pass


def count_cat(table):
    try:
        count = session.query(func.count(table.id)).scalar()
        return count
    except:
        pass


def count_items(category_id):
    try:
        count = session.query(func.count(association.c.item_id)).filter(
            association.c.category_id == category_id).scalar()
        return count
    except:
        pass


# UPDATE


def update(table, data, kwargs):
    if 'user_id' in login_session:
        user_id = login_session['user_id']
        if not user_id:
            return make_response(jsonify({
                "message": "Need a valid user id"}), 401)
    row = session.query(table).filter_by(**kwargs).first()
    if row is None:
        return make_response(jsonify(
            {"message": "Could not find any row"}))
    elif user_id != row.user_id:
        return make_response(jsonify(
            {"message": "You do not have permission to edit this row"}), 405)

    if 'name' in data:
        name = data['name'].strip().lower().capitalize()
        if name == "":
            return make_response(jsonify(
                {"message": "Need a valid name"}))
    if name != row.name:
        exist = get_first(table, {"name": name})
        if exist is not None:
            return make_response(jsonify(
                {"message": "That name has already been taken"}))
    if table == Item:
        if 'description' in data and data['description'] is not None:
            description = data['description']
        else:
            description = row.description
        if 'categories' in data and data['categories'] is not None:
            if isinstance(data['categories'], list):
                categories = data['categories']
            else:
                categories = data.getlist('categories')
        else:
            categories = []
            for category in row.categories:
                categories.append(category.id)
        if categories == [] or not isinstance(categories, list):
            return make_response(jsonify(
                {"message": "Need valid category ID(s) as array"}))

    row.name = name

    if table == Item:
        row.description = description
        exist = session.query(Category).filter(
            Category.id.in_(categories)).all()
        if exist:
            row.categories = []
            row.categories.extend(exist)

    session.commit()
    return row


# DELETE
def delete(table, kwargs):
    if 'user_id' in login_session:
        user_id = login_session['user_id']
        if not user_id:
            return make_response(jsonify(
                {"message": "Need a valid user id"}), 401)
    row = get_first(table, kwargs)
    if row is None:
        return make_response(jsonify(
            {"message": "Could not find any row"}), 404)
    elif user_id != row.user_id:
        return make_response(jsonify(
            {"message": "You do not have permission to delete this row"}), 405)
    elif row is not None:
        try:
            session.delete(row)
            session.commit()
            return row
        except:
            pass
    else:
        return None


def get_first(table, kwargs):
    try:
        row = session.query(table).filter_by(**kwargs).first()
        return row
    except:
        pass


def get_one(table, kwargs):
    try:
        row = session.query(table).filter_by(**kwargs).one()
        return row
    except:
        pass


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Obtain data from POST request
    data = json.loads(request.data)
    # Validate state token
    state = data['state']
    if state != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code
    code = data['code']
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
    result = json.loads(h.request(url, 'GET')[1])
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
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
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

    login_session['name'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one

    user = get_first(User, {"email": data["email"]})
    if user is not None:
        user_id = user.id
    else:
        user_id = createUser(login_session)

    login_session['user_id'] = user_id

    output = "Welcome, {}.".format(login_session['name'])
    flash("You are now logged in as {}".format(login_session['name']))
    return output


@app.route('/fbconnect', methods=['POST'])
def fbconnect():

    # Obtain data from POST request
    data = json.loads(request.data)
    # Validate state token
    state = data['state']
    if state != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code
    access_token = data['access_token']

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/\
    access_token?grant_type=fb_exchange_token&client_id={}&\
    client_secret={}&fb_exchange_token={}'.format(
        app_id, app_secret, access_token)
    result = httplib2.Http().request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token
        exchange we have to split the token first on commas and select
        the first index which gives us the key : value for the server
        access token then we split it on colons to pull out the actual
        token value and replace the remaining quotes with nothing so that
        it can be used directly in the graph api calls
    '''
    access_token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?\
    access_token={}&fields=name,id,email'.format(
        access_token)
    result = httplib2.Http().request(url, 'GET')[1]
    data = json.loads(result)

    login_session.update({
        'access_token': access_token,
        'facebook_id': data["id"],
        'name': data["name"],
        'email': data["email"],
        'provider': 'facebook'
    })

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?\
    access_token={}&redirect=0&height=200&width=200'.format(
        access_token)
    result = httplib2.Http().request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user = get_first(User, {"email": login_session['email']})
    if user is not None:
        user_id = user.id
    else:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = "Welcome, {}.".format(login_session['name'])
    flash("Now logged in as %s" % login_session['name'])
    return output


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
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:

        if 'provider' in login_session == 'google':
            gdisconnect()
        if 'provider' in login_session == 'facebook':
            fbdisconnect()
        if 'provider' in login_session:
            del login_session['provider']
        if 'username' in login_session:
            del login_session['username']
        if 'name' in login_session:
            del login_session['name']
        if 'email' in login_session:
            del login_session['email']
        if 'user_id' in login_session:
            del login_session['user_id']
        if 'picture' in login_session:
            del login_session['picture']
        if 'access_token' in login_session:
            del login_session['access_token']
        if 'gplus_id' in login_session:
            del login_session['gplus_id']
        if 'facebook_id' in login_session:
            del login_session['facebook_id']

        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))


@app.route('/populateDatabase')
def populateDatabase():
    create(Category, {"name": "test-category"})
    create(Item, {"name": "test-item",
                  "description": "this is a test", "categories": [1]})


@auth.verify_password
def verify_password(email_or_token, password):
    # Try to see if it's a token first
    user_id = User.verify_auth_token(email_or_token)
    if user_id:
        user = get_one(User, {"id": user_id})
    else:
        user = get_first(User, {"email": email_or_token})
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


def getWikiInfo(title):
    S = requests.Session()
    URL = "https://en.wikipedia.org/w/api.php"
    PARAMS = {
        'action': "query",
        'format': "json",
        'prop': 'extracts',
        'exintro': 1,
        'explaintext': 1,
        'redirects': 1,
        'titles': title,
    }

    try:
        data = S.get(url=URL, params=PARAMS).json()
        if data:
            pages = json.dumps(data['query']['pages'])
        if pages:
            wiki_page = next(iter(json.loads(
                pages, object_pairs_hook=OrderedDict).values()))
        if wiki_page:
            wiki_page['title'] = (
                wiki_page['title']).strip().lower().capitalize()
            return wiki_page
    except:
        return None


def getWikiCategories(title):
    S = requests.Session()
    URL = "https://en.wikipedia.org/w/api.php"
    PARAMS = {
        'action': "query",
        'format': "json",
        'titles': title,
        'prop': 'categories'
    }
    try:
        data = S.get(url=URL, params=PARAMS).json()
        if data:
            pages = json.dumps(data['query']['pages'])
        if pages:
            wiki_cats = next(iter(json.loads(
                pages, object_pairs_hook=OrderedDict).values()))[
                'categories']
        if wiki_cats:
            wiki_categories = []
            for i in wiki_cats:
                wiki_categories.append(i['title'].split(
                    'Category:', 1)[1])
            return wiki_categories
    except:
        return None


@app.after_request
def store_visted_urls(response):
    if 'last_visited' not in login_session:
        login_session['last_visited'] = ["/catalog/"]
    if 'last_visited' in login_session:
        path = "{}".format(request.path)
        f_word = "{}".format(request.path).split('/', 2)[1]
        data = prepareData()
        if isinstance(data, dict) and \
                'search' in data and data['search'] is not None:
            q = data['search']
            path += "?search={}".format(q)
        if f_word != 'static' and \
                login_session['last_visited'][-1] != "{}".format(path):
            login_session['last_visited'].append("{}".format(path))
    while len(login_session['last_visited']) > 4:
        login_session['last_visited'].pop(0)
    login_session.modified = True
    return response


# Run test server
if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"
    # context = ('server.crt', 'server.key')
    app.secret_key = 'super_secret_key'
    app.run(host='0.0.0.0', port=8000, debug=True)
    # app.run(host='0.0.0.0', port=8000, debug=True, ssl_context=context)
