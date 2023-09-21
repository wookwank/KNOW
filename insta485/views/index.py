"""
Insta485 index (main) view.

URLs include:
/
"""

import arrow
import flask
import hashlib
import pathlib
import uuid
import insta485

# Helper functions library
@insta485.app.context_processor
def helpers():
    """Define dictionary of helpers."""
    def timestamp_handler(timestamp):
        utc = arrow.get(timestamp, tzinfo='America/New_York')
        return utc.humanize()
    return dict(timestamp_handler=timestamp_handler)

# Helper for routing images
@insta485.app.route('/uploads/<path:filename>')
def static_file(filename):
    """Resolve image path."""
    path_app_var = insta485.app.config['UPLOADS_FOLDER']
    return flask.send_from_directory(path_app_var, filename)


# Routing function for /
@insta485.app.route('/')
def show_index():
    """Display / route."""
    # not logged in
    # redirect to accounts/login
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    
    # logged in
    # set logname to logname in cookies (flask.session)
    logname = flask.session['logname']
    
    # Connect to database
    connection = insta485.model.get_db()

    # Hard Coded logname
    # logname = "awdeorio"

    # Query users
    users = connection.execute(
        "SELECT username, filename FROM users"
    )
    users = users.fetchall()

    # Query posts
    posts = connection.execute(
        "SELECT * FROM posts "
        "WHERE owner = ? OR "
        "(owner IN (SELECT username1 "
        "FROM following WHERE username2 = ?))", (logname,logname)
    )
    posts = posts.fetchall()

    # Query comments
    comments = connection.execute(
        "SELECT owner, text, postid FROM comments"
    )
    comments = comments.fetchall()

    # Query likes
    likes = connection.execute(
        "SELECT postid, owner FROM likes"
    )
    likes = likes.fetchall()

    # Add database info to context
    context = {
        "logname" : logname, 
        "posts" : posts,
        "comments" : comments,
        "users" : users,
        "likes" : likes
    }
    return flask.render_template("index.html", **context)

@insta485.app.route('/users/<path:username>/')
def show_user(username):
    """Display /users/<path:username> route."""
    # Connect to database
    connection = insta485.model.get_db()

    # Hard Coded logname
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    logname = flask.session['logname']

    # Query users
    users = connection.execute(
        "SELECT username, fullname FROM users"
    )
    users = users.fetchall()

    # Abort if username is not in db
    if username not in [user['username'] for user in users]:
        flask.abort(404)

    # Query posts
    posts = connection.execute(
        "SELECT postid, filename, owner FROM posts "
    )
    posts = posts.fetchall()

    # Query following
    following = connection.execute(
        "SELECT username1, username2 FROM following "
    )
    followers = following.fetchall()

    context = {
        "logname" : logname,
        "username" : username, 
        "users" : users,
        "posts" : posts,
        "followers" : followers
    }
    return flask.render_template("user.html", **context)


@insta485.app.route('/users/<path:username>/followers/')
def show_followers(username):
     # Connect to database
    connection = insta485.model.get_db()

    #  logname
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    logname = flask.session['logname']

    # Query following
    followers = connection.execute(
            "SELECT username1, username2 FROM following"
    )
    followers = followers.fetchall()

    # Query users
    users = connection.execute(
        "SELECT username, filename FROM users"
    )
    users = users.fetchall()

    # Abort if username is not in db
    if username not in [user['username'] for user in users]:
        flask.abort(404)

    context = {
        "username" : username,
        "logname" : logname,
        "followers" : followers,
        "users" : users
    }
    return flask.render_template("followers.html", **context)

@insta485.app.route('/users/<path:username>/following/')
def show_following(username):
    # Connect to database
    connection = insta485.model.get_db()

    # logname
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    logname = flask.session['logname']

    # Query following
    followers = connection.execute(
            "SELECT username1, username2 FROM following"
    )
    followers = followers.fetchall()

    # Query users
    users = connection.execute(
        "SELECT username, filename FROM users"
    )
    users = users.fetchall()

    # Abort if username is not in db
    if username not in [user['username'] for user in users]:
        flask.abort(404)

    context = {
        "username" : username,
        "logname" : logname,
        "followers" : followers,
        "users" : users
    }
    return flask.render_template("following.html", **context)
    

@insta485.app.route('/posts/<int:postid>/')
def show_posts(postid):
    """Display / route."""
    # Connect to database
    connection = insta485.model.get_db()

    #  logname
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    logname = flask.session['logname']

    # Query users
    users = connection.execute(
        "SELECT username, filename FROM users"
    )
    users = users.fetchall()

    # Query posts
    posts = connection.execute(
        "SELECT * FROM posts "
    )
    posts = posts.fetchall()

    # Query comments
    comments = connection.execute(
        "SELECT owner, text, postid, commentid FROM comments"
    )
    comments = comments.fetchall()

    # Query likes
    likes = connection.execute(
        "SELECT postid, owner FROM likes"
    )
    likes = likes.fetchall()

    # Add database info to context
    context = {
        "postid" : postid,
        "logname" : logname, 
        "posts" : posts,
        "comments" : comments,
        "users" : users,
        "likes" : likes
    }
    return flask.render_template("post.html", **context)

@insta485.app.route('/explore/')
def show_explore():
    # Connect to database
    connection = insta485.model.get_db()

    #  logname
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    logname = flask.session['logname']

    users = connection.execute(
        "SELECT username, filename FROM users"
    )
    users = users.fetchall()

    # Query following
    following = connection.execute(
        "SELECT username2 FROM following WHERE username1 = ?", (logname,)
    )
    following = following.fetchall()
    following = [follow['username2'] for follow in following]

    context = {
        "logname" : logname,
        "users" : users,
        "following" : following
    }
    return flask.render_template("explore.html", **context)


@insta485.app.route('/accounts/login/')
def show_login():
    if 'logname' in flask.session:
        return flask.redirect(flask.url_for('show_index'))
    return flask.render_template("login.html")


@insta485.app.route('/accounts/logout/', methods=['POST'])
def post_logout():
    # 이유 설명
    # if 'logname' not in flask.session:
    #     return flask.redirect(flask.url_for('show_login'))
    # logname = flask.session['logname']
    
    # flask.session['logname'] = None
    flask.session.clear()
    return flask.redirect(flask.url_for('show_login'))


@insta485.app.route('/accounts/create/')
def show_create():
    if 'logname' in flask.session:
        return flask.redirect(flask.url_for('show_edit'))
    return flask.render_template("create.html")


@insta485.app.route('/accounts/delete/')
def show_delete():
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    logname = flask.session['logname']

    context = {
        "logname" : logname
    }

    return flask.render_template("delete.html", **context)


@insta485.app.route('/accounts/edit/')
def show_edit():
    #  logname
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    logname = flask.session['logname']
    # check how to get email 
    # email = flask.session['email']
    context = {
        "logname" : logname,
        # "email" : email
    }
    return flask.render_template("edit.html", **context)


@insta485.app.route('/accounts/password/')
def show_password():
    #  logname
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    logname = flask.session['logname']

    context = {
        "logname" : logname
    }

    return flask.render_template("password.html", **context)

@insta485.app.route('/accounts/auth/')
def show_auth():
    if 'logname' in flask.session:
        return flask.make_response('', 200)
    return flask.abort(403)

@insta485.app.route('/accounts/', methods=['POST'])
def post_account():

     # Connect to database
    connection = insta485.model.get_db()

    users = connection.execute(
        "SELECT username, password, filename FROM users"
    )
    users = users.fetchall()

    posts = connection.execute(
        "SELECT filename, owner FROM posts"
    )
    posts = posts.fetchall()

    operation = flask.request.form.get('operation')
    target_url = flask.request.args.get('target')
   
    match operation:
        case 'login':
            username = flask.request.form.get('username')
            password = flask.request.form.get('password')
            
            # username or password is empty
            if not username or not password:
                flask.abort(400)

            # case for username and password authentication fail
            # user does not exist in db
            if username not in [user['username'] for user in users]:
                flask.abort(403)
            # user exists
            else:
                for user in users:
                    if user['username'] == username:
                        if user['password'] != password:
                            flask.abort(403)
            #compare hashed password and user input
            # set session
            flask.session['logname'] = username
                
        case 'create':
            # Use from POST request 
            username = flask.request.form.get('username')
            password = flask.request.form.get('password')
            fullname = flask.request.form.get('fullname')
            email = flask.request.form.get('email')
            file = flask.request.files['file']

            # If any are empty, abort(400)
            if (not username
                or not password
                or not fullname
                or not email
                or not file.filename):
                flask.abort(400)

            
            # if user tries to make username that exists in db
            if username in [user['username'] for user in users]:
                flask.abort(409)

            # password hashing
            algorithm = 'sha512'
            salt = uuid.uuid4().hex
            hash_obj = hashlib.new(algorithm)
            password_salted = salt + password
            hash_obj.update(password_salted.encode('utf-8'))
            password_hash = hash_obj.hexdigest()
            password_db_string = "$".join([algorithm, salt, password_hash])

            # insert info into db
            cursor = connection.cursor()
            cursor.execute(
                "INSERT INTO users "
                "(username, password, fullname, email, filename)"
                "VALUES (?, ?, ?, ?, ?)",
                (username, password_db_string, fullname, email, file.filename)
            )

            # compute base name
            stem = uuid.uuid4().hex
            suffix = pathlib.Path(file.filename).suffix.lower()
            uuid_basename = f"{stem}{suffix}"

            # save to disk
            path = insta485.app.config["UPLOADS_FOLDER"] / uuid_basename
            file.save(path)

            # log the user in and redirect to target url
            flask.session['logname'] = username
        
        case 'delete':
            # if user is not logged in abort
            if 'logname' not in flask.session:
                flask.abort(403)
            logname = flask.session['logname']

            # delete post files created by user
            for post in posts:
                if post['owner'] == logname:
                    filename = post['filename']
                    path = insta485.app.config["UPLOADS_FOLDER"] / filename
                    path.unlink()

            # delete user icon file
            for user in users:
                if user['username'] == logname:
                    filename = user['filename']
                    path = insta485.app.config["UPLOADS_FOLDER"] / filename
                    path.unlink()
                    
            # delete all related entries in all tables
            cursor = connection.cursor()
            cursor.execute(
                "DELETE FROM users WHERE username = ?",
                (logname,)
            )

            # redirect to URL
            flask.session.clear()
        
        case 'edit_account':
            pass
        case 'update_password':
            pass
    
    if not target_url:
        return flask.redirect(flask.url_for('show_index'))
    return flask.redirect(target_url)



