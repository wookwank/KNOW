"""
Insta485 index (main) view.

URLs include:
/
"""
from flask import send_from_directory
import flask
import insta485


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

    # Add database info to context
    context = {
        "logname" : logname, 
        "posts" : posts,
        "comments" : comments,
        "users" : users
    }
    return flask.render_template("index.html", **context)

@insta485.app.route('/<path:filename>')
def static_file(filename):
    path_app_var = insta485.app.config['UPLOAD_FOLDER']
    return send_from_directory(path_app_var, filename)