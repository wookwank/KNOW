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
import KNOW


# Helper functions for jinja templating
@KNOW.app.context_processor
def helpers():
    """Define dictionary of helpers."""
    def timestamp_handler(timestamp):
        utc = arrow.get(timestamp)
        return utc.humanize()
    return {"timestamp_handler": timestamp_handler}

# Routing function for /
@KNOW.app.route('/')
def show_index():
    return flask.render_template("login.html")

@KNOW.app.route('/accounts/login/')
def show_login():
    """Login users."""
    return flask.render_template("login.html")

@KNOW.app.route('/accounts/create/')
def show_create():
    """Create users."""
    return flask.render_template("create.html")

@KNOW.app.route('/accounts/', methods=['POST'])
def account_ops():
    """Create users."""
    operation = flask.request.form.get('operation')
    
    match operation:
        case 'login':
            username = flask.request.form.get('username')
            password = flask.request.form.get('password')

            if (username == "guest" and password == "password"):
                return
        case 'create':
            flask.request.form.get('username')
            flask.request.form.get('password')
            flask.request.form.get('fullname')
            flask.request.form.get('email')
    
    return flask.render_template("index.html")



@KNOW.app.route('/users/<path:username>/')
def show_user(username):
    """Display /users/<path:username> route."""
    # Connect to database
    connection = KNOW.model.get_db()

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

@KNOW.app.route('/posts/<int:postid>/')
def show_posts(postid):
    """Display / route."""
    # Connect to database
    connection = KNOW.model.get_db()

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


@KNOW.app.route('/explore/')
def show_explore():
    """Explore users."""
    # Connect to database
    connection = KNOW.model.get_db()

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



@KNOW.app.route('/accounts/logout/', methods=['POST'])
def post_logout():
    """Logout users."""
    flask.session.clear()
    return flask.redirect(flask.url_for('show_login'))


@KNOW.app.route('/accounts/delete/')
def show_delete():
    """Delete users."""
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    logname = flask.session['logname']

    context = {
        "logname": logname
    }

    return flask.render_template("delete.html", **context)

@KNOW.app.route('/accounts/edit/')
def show_edit():
    """Edit user information."""
    #  logname
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    logname = flask.session['logname']

    connection = KNOW.model.get_db()
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


@KNOW.app.route('/accounts/password/')
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


@KNOW.app.route('/accounts/', methods=['POST'])
def post_account():
    """Manage user information (login/delete/create/edit/update)."""
    # Connect to database
    connection = KNOW.model.get_db()

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


@KNOW.app.route('/posts/', methods=['POST'])
def post_posts():
    """Manage post creation and deletion."""
    # Connect to database
    connection = KNOW.model.get_db()
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
            path = KNOW.app.config["UPLOADS_FOLDER"] / uuid_basename
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
                    path = KNOW.app.config["UPLOADS_FOLDER"] / filename
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
