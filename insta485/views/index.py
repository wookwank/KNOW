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
        return arrow.get(timestamp).humanize()
    return dict(timestamp_handler=timestamp_handler)

# Helper for routing images
@insta485.app.route('/<path:filename>')
def static_file(filename):
    """Resolve image path."""
    path_app_var = insta485.app.config['UPLOAD_FOLDER']
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
        "SELECT * FROM posts"
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
