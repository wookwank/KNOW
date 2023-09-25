"""
Insta485 index (main) view.

URLs include:
/
"""
import hashlib
import pathlib
import os
import uuid
import flask
import arrow
import insta485


# Helper functions for jinja templating
@insta485.app.context_processor
def helpers():
    """Define dictionary of helpers."""
    def timestamp_handler(timestamp):
        utc = arrow.get(timestamp)
        return utc.humanize()
    return {"timestamp_handler": timestamp_handler}


# Helper for routing images
@insta485.app.route('/uploads/<path:filename>')
def static_file(filename):
    """Resolve image path."""
    path_app_var = insta485.app.config['UPLOADS_FOLDER']
    if 'logname' not in flask.session:
        flask.abort(403)
    if filename not in os.listdir(path_app_var):
        flask.abort(404)

    return flask.send_from_directory(path_app_var, filename)


# Helper function for hashing password
def hash_password(salt, password):
    """Hash password."""
    algorithm = 'sha512'
    hash_obj = hashlib.new(algorithm)
    salted = salt + password
    hash_obj.update(salted.encode('utf-8'))
    hashed = hash_obj.hexdigest()
    password_string = "$".join([algorithm, salt, hashed])
    return password_string


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

    # Query users
    users = connection.execute(
        "SELECT username, filename FROM users"
    )
    users = users.fetchall()

    # Query following
    following = connection.execute(
        "SELECT username1, username2 FROM following "
    )
    following = following.fetchall()

    # Query posts
    posts = connection.execute(
        "SELECT * FROM posts "
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
        "logname": logname,
        "posts": posts,
        "comments": comments,
        "users": users,
        "likes": likes,
        "following": following
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
        "logname": logname,
        "username": username,
        "users": users,
        "posts": posts,
        "followers": followers
    }
    return flask.render_template("user.html", **context)


@insta485.app.route('/users/<path:username>/followers/')
def show_followers(username):
    """Show followers."""
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
        "username": username,
        "logname": logname,
        "followers": followers,
        "users": users
    }
    return flask.render_template("followers.html", **context)


@insta485.app.route('/users/<path:username>/following/')
def show_following(username):
    """Show following."""
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
        "username": username,
        "logname": logname,
        "followers": followers,
        "users": users
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
        "postid": postid,
        "logname": logname,
        "posts": posts,
        "comments": comments,
        "users": users,
        "likes": likes
    }
    return flask.render_template("post.html", **context)


@insta485.app.route('/explore/')
def show_explore():
    """Explore users."""
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
        "logname": logname,
        "users": users,
        "following": following
    }
    return flask.render_template("explore.html", **context)


@insta485.app.route('/accounts/login/')
def show_login():
    """Login users."""
    if 'logname' in flask.session:
        return flask.redirect(flask.url_for('show_index'))
    return flask.render_template("login.html")


@insta485.app.route('/accounts/logout/', methods=['POST'])
def post_logout():
    """Logout users."""
    flask.session.clear()
    return flask.redirect(flask.url_for('show_login'))


@insta485.app.route('/accounts/create/')
def show_create():
    """Create users."""
    if 'logname' in flask.session:
        return flask.redirect(flask.url_for('show_edit'))
    return flask.render_template("create.html")


@insta485.app.route('/accounts/delete/')
def show_delete():
    """Delete users."""
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    logname = flask.session['logname']

    context = {
        "logname": logname
    }

    return flask.render_template("delete.html", **context)


@insta485.app.route('/accounts/edit/')
def show_edit():
    """Edit user information."""
    #  logname
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    logname = flask.session['logname']

    connection = insta485.model.get_db()
    filename = connection.execute(
        "SELECT filename FROM users WHERE "
        "username = ? ",
        (logname,)
    )
    filename = filename.fetchall()[0]['filename']

    context = {
        "logname": logname,
        "filename": filename
    }
    return flask.render_template("edit.html", **context)


@insta485.app.route('/accounts/password/')
def show_password():
    """Edit user password."""
    #  logname
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    logname = flask.session['logname']

    context = {
        "logname": logname
    }

    return flask.render_template("password.html", **context)


@insta485.app.route('/accounts/auth/')
def show_auth():
    """Authenticate users."""
    if 'logname' in flask.session:
        return flask.make_response('', 200)
    return flask.abort(403)


def post_account_login(connection, *args):
    """Login user, helper for post account."""
    (username, password) = args
    # fetch users from db
    users = connection.execute(
        "SELECT username, password, filename FROM users"
    )
    users = users.fetchall()

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
                # Hash input with salt obtained from password
                password_hashed = hash_password(
                    user['password'].split('$')[1],
                    password
                    )
                if user['password'] != password_hashed:
                    flask.abort(403)

    # compare hashed password and user input
    # set session
    flask.session['logname'] = username


def post_account_create(connection, *args):
    """Create user, helper for post account."""
    (username, password, fullname, email, file) = args
    # fetch users from db
    users = connection.execute(
        "SELECT username, password, filename FROM users"
    )
    users = users.fetchall()

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

    # compute base name
    stem = uuid.uuid4().hex
    suffix = pathlib.Path(file.filename).suffix.lower()
    uuid_basename = f"{stem}{suffix}"

    # save to disk
    path = insta485.app.config["UPLOADS_FOLDER"] / uuid_basename
    file.save(path)

    # password hashing
    password_db_string = hash_password(uuid.uuid4().hex, password)

    # insert info into db
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO users "
        "(username, password, fullname, email, filename)"
        "VALUES (?, ?, ?, ?, ?)",
        (username, password_db_string, fullname, email, uuid_basename)
    )

    # log the user in and redirect to target url
    flask.session['logname'] = username


def post_account_delete(connection):
    """Delete user, helper for post account."""
    # fetch users from db
    users = connection.execute(
        "SELECT username, password, filename FROM users"
    )
    users = users.fetchall()

    posts = connection.execute(
        "SELECT filename, owner FROM posts"
    )
    posts = posts.fetchall()

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


def post_account_edit_account(connection, *args):
    """Edit user account, helper for post account."""
    (fullname, email, file) = args
    # fecth users from db
    users = connection.execute(
        "SELECT username, password, filename FROM users"
    )
    users = users.fetchall()

    # if user is not logged in abort
    if 'logname' not in flask.session:
        flask.abort(403)
    logname = flask.session['logname']

    # username or password is empty
    if not fullname or not email:
        flask.abort(400)

    # delete user icon file
    for user in users:
        if user['username'] == logname:
            path = (insta485.app.config["UPLOADS_FOLDER"] /
                    user['filename'])
            path.unlink()

    # update user photo into db
    # compute base name
    stem = uuid.uuid4().hex
    suffix = pathlib.Path(file.filename).suffix.lower()
    uuid_basename = f"{stem}{suffix}"

    # save to disk
    path = insta485.app.config["UPLOADS_FOLDER"] / uuid_basename
    file.save(path)

    cursor = connection.cursor()
    # if there is no photo
    if not file.filename:
        cursor.execute(
            "UPDATE users SET "
            "(fullname, email) ="
            "(?, ?) WHERE username = ?",
            (fullname, email, logname)
        )
    # if a photo exists
    else:
        # update
        cursor.execute(
            "UPDATE users SET "
            "(fullname, email, filename) = "
            "(?, ?, ?) WHERE username = ?",
            (fullname, email, uuid_basename, logname)
        )


def post_account_update_password(connection, *args):
    """Update user password, helper for post account."""
    (password_input, new_password1, new_password2) = args
    # fecth users from db
    users = connection.execute(
        "SELECT username, password, filename FROM users"
    )
    users = users.fetchall()

    # If user is not logged in abort
    if 'logname' not in flask.session:
        flask.abort(403)
    logname = flask.session['logname']

    # One of the fields are empty
    if not password_input or not new_password1 or not new_password2:
        flask.abort(400)

    # Check for password match. if no match, abort 403
    for user in users:
        if user['username'] == logname:
            # Hash input with salt obtained from password
            hashed_in = hash_password(
                user['password'].split('$')[1],
                password_input
                )
            if user['password'] != hashed_in:
                flask.abort(403)

    # Two passwords don't match
    if new_password1 != new_password2:
        flask.abort(401)

    # Hash new password
    new_password_db_string = hash_password(uuid.uuid4().hex, new_password1)

    # Update database
    cursor = connection.cursor()
    cursor.execute(
        "UPDATE users SET "
        "password = ? "
        "WHERE username = ?",
        (new_password_db_string, logname, )
    )


@insta485.app.route('/accounts/', methods=['POST'])
def post_account():
    """Manage user information (login/delete/create/edit/update)."""
    # Connect to database
    connection = insta485.model.get_db()

    # fetch operation type
    operation = flask.request.form.get('operation')

    match operation:
        case 'login':
            post_account_login(
                connection,
                flask.request.form.get('username'),
                flask.request.form.get('password')
            )

        case 'create':
            post_account_create(
                connection,
                flask.request.form.get('username'),
                flask.request.form.get('password'),
                flask.request.form.get('fullname'),
                flask.request.form.get('email'),
                flask.request.files['file']
            )

        case 'delete':
            post_account_delete(connection)

        case 'edit_account':
            post_account_edit_account(
                connection,
                flask.request.form.get('fullname'),
                flask.request.form.get('email'),
                flask.request.files['file']
            )

        case 'update_password':
            post_account_update_password(
                connection,
                flask.request.form.get('password'),
                flask.request.form.get('new_password1'),
                flask.request.form.get('new_password2')
            )

    target_url = flask.request.args.get('target')

    if not target_url:
        return flask.redirect(flask.url_for('show_index'))
    return flask.redirect(target_url)


@insta485.app.route('/likes/', methods=['POST'])
def post_likes():
    """Manage likes in the post."""
    # Connect to database
    connection = insta485.model.get_db()
    logname = flask.session['logname']

    likes = connection.execute(
        "SELECT * FROM likes"
    )
    likes = likes.fetchall()

    operation = flask.request.form.get('operation')
    postid = int(flask.request.form.get('postid'))
    target_url = flask.request.args.get('target')

    cursor = connection.cursor()
    match operation:
        case 'like':
            # tries to like when user already liked
            for like in likes:
                if like['owner'] == logname and like['postid'] == postid:
                    flask.abort(409)

            # if like does not exist, like
            cursor.execute(
                "INSERT INTO likes "
                "(owner, postid)"
                "VALUES (?, ?) ",
                # should we add postid = now?
                (logname, postid)
            )

        case 'unlike':
            # there exists a like from the user (logname)
            liked = False
            for like in likes:
                if like['owner'] == logname and like['postid'] == postid:
                    liked = True
                    cursor.execute(
                        "DELETE FROM likes WHERE "
                        "owner = ? and postid = ?",
                        (logname, postid)
                    )

            # user tries to unlike a post that he did not like
            if not liked:
                flask.abort(409)

    if not target_url:
        return flask.redirect(flask.url_for('show_index'))
    return flask.redirect(target_url)


@insta485.app.route('/comments/', methods=['POST'])
def post_comments():
    """Manage comments in the post."""
    # Connect to database
    connection = insta485.model.get_db()
    comments = connection.execute(
        "SELECT * FROM comments"
    )
    comments = comments.fetchall()

    logname = flask.session['logname']
    operation = flask.request.form.get('operation')
    text = flask.request.form.get('text')
    target_url = flask.request.args.get('target')

    cursor = connection.cursor()
    match operation:
        case 'create':
            postid = int(flask.request.form.get('postid'))
            if not text:
                flask.abort(400)
            cursor.execute(
                "INSERT INTO comments "
                "(owner, postid, text)"
                "VALUES (?, ?, ?) ",
                (logname, postid, text)
            )
        case 'delete':
            # if user tries to delete comment they do not own
            commentid = int(flask.request.form.get('commentid'))
            comment_owner = False
            for comment in comments:
                if (comment['commentid'] == commentid and
                        comment['owner'] == logname):
                    comment_owner = True
                    cursor.execute(
                        "DELETE FROM comments WHERE "
                        "commentid = ? and owner = ?",
                        (commentid, logname)
                    )

            if not comment_owner:
                flask.abort(403)

    if not target_url:
        return flask.redirect(flask.url_for('show_index'))
    return flask.redirect(target_url)


@insta485.app.route('/posts/', methods=['POST'])
def post_posts():
    """Manage post creation and deletion."""
    # Connect to database
    connection = insta485.model.get_db()
    posts = connection.execute(
        "SELECT * FROM posts"
    )
    posts = posts.fetchall()

    logname = flask.session['logname']
    operation = flask.request.form.get('operation')
    target_url = flask.request.args.get('target')

    cursor = connection.cursor()
    match operation:
        case 'create':
            file = flask.request.files['file']
            # check for file exists
            if not file.filename:
                flask.abort(400)
            # update photo into db
            # compute base name
            stem = uuid.uuid4().hex
            suffix = pathlib.Path(file.filename).suffix.lower()
            uuid_basename = f"{stem}{suffix}"

            # save to disk
            path = insta485.app.config["UPLOADS_FOLDER"] / uuid_basename
            file.save(path)

            cursor.execute(
                "INSERT INTO posts "
                "(filename, owner) "
                "VALUES (?, ?)",
                (uuid_basename, logname)
            )

        case 'delete':
            postid = int(flask.request.form.get('postid'))
            am_post_owner = False
            for post in posts:
                if post['postid'] == postid and post['owner'] == logname:
                    am_post_owner = True
                    filename = post['filename']
                    path = insta485.app.config["UPLOADS_FOLDER"] / filename
                    path.unlink()
                    cursor.execute(
                        "DELETE FROM posts WHERE "
                        "postid = ? and owner = ?",
                        (postid, logname)
                    )
                    cursor.execute(
                        "DELETE FROM likes WHERE "
                        "postid = ? and owner = ?",
                        (postid, logname)
                    )
                    cursor.execute(
                        "DELETE FROM comments WHERE "
                        "postid = ? and owner = ?",
                        (postid, logname)
                    )

            if not am_post_owner:
                flask.abort(403)

    if not target_url:
        return flask.redirect(flask.url_for('show_user', username=logname))
    return flask.redirect(target_url)


@insta485.app.route('/following/', methods=['POST'])
def post_following():
    """Manage followers."""
    # connect to database
    connection = insta485.model.get_db()

    logname = flask.session['logname']
    username = flask.request.form.get('username')
    operation = flask.request.form.get('operation')
    target_url = flask.request.args.get('target')

    following = connection.execute(
        "SELECT * FROM following"
    )
    following = following.fetchall()

    cursor = connection.cursor()
    match operation:
        case 'follow':
            for follow in following:
                if (follow['username1'] == logname and
                        follow['username2'] == username):
                    flask.abort(409)

            cursor.execute(
                "INSERT INTO following "
                "(username1, username2) "
                "VALUES (?, ?)",
                (logname, username)
            )

        case 'unfollow':
            follows = False
            for follow in following:
                follows = True
                if (follow['username1'] == logname and
                        follow['username2'] == username):
                    cursor.execute(
                        "DELETE FROM following WHERE "
                        "username1 = ? and username2 = ?",
                        (logname, username)
                    )
            if not follows:
                flask.abort(409)

    if not target_url:
        return flask.redirect(flask.url_for('show_index'))
    return flask.redirect(target_url)
