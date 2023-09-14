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

    # Query database
    logname = "awdeorio"
    post = connection.execute(
        "SELECT * FROM posts"
    )
    com = connection.execute(
        "SELECT owner, text, postid FROM comments"
    )
    posts = post.fetchall()
    comments = com.fetchall()

    # Add database info to context
    context = {
        "logname" : logname, 
        "posts" : posts,
        "comments" : comments
    }
    return flask.render_template("index.html", **context)

@insta485.app.route('/')
def static_file(filename):
    return send_from_directory(insta485.app.config['UPLOAD_FOLDER'], filename, as_attachment=False)