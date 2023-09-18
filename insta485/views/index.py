"""
Insta485 index (main) view.

URLs include:
/
"""

import arrow
import flask
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
    # Connect to database
    connection = insta485.model.get_db()

    # Hard Coded logname
    logname = "awdeorio"

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
        "SELECT postid FROM likes"
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
    logname = "awdeorio"

    # Query users
    users = connection.execute(
        "SELECT username, fullname FROM users"
    )
    users = users.fetchall()

    # Query posts
    posts = connection.execute(
        "SELECT postid, filename, owner FROM posts "
    )
    posts = posts.fetchall()


    context = {
        "logname" : logname,
        "users" : users
        "posts" : posts
    }
    return flask.render_template("user.html", **context)


@insta485.app.route('/users/<path:username>/following/')
def show_following(username):
    context = {

    }
    return flask.render_template("following.html", **context)

@insta485.app.route('/users/<path:username>/followers/')
def show_followers(username):
    context = {

    }
    return flask.render_template("followers.html", **context)

@insta485.app.route('/posts/<path:postid>/')
def show_posts(postid):
    context = {

    }
    return flask.render_template("post.html", **context)

@insta485.app.route('/explore/')
def show_explore():
    context = {

    }
    return flask.render_template("explore.html", **context)
