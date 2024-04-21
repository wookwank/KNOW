import flask
import KNOW

# Routing function for /
@KNOW.app.route('/')
def show_index():
    return flask.render_template("login.html")

@KNOW.app.route('/accounts/create/')
def show_create():
    """Create users."""
    return flask.render_template("create.html")

@KNOW.app.route('/landing1/')
def show_landing_input():
    """Show landing page."""
    return flask.render_template("landing_input.html")

@KNOW.app.route('/landing2/')
def show_landing_output():
    """Show landing page."""
    return flask.render_template("landing_output.html")

@KNOW.app.route('/profile/')
def show_profile():
    """Show landing page."""
    return flask.render_template("profile.html")

@KNOW.app.route('/setting/')
def show_setting():
    """Show landing page."""
    return flask.render_template("setting.html")

@KNOW.app.route('/translation/')
def show_translation():
    """Show landing page."""
    return flask.render_template("translation.html")

@KNOW.app.route('/accounts/', methods=['POST'])
def account_ops():
    """Create users."""
    operation = flask.request.form.get('operation')
    
    match operation:
        case 'login':
            username = flask.request.form.get('username')
            password = flask.request.form.get('password')

            if (username != "guest" or password != "password"):
                return
        case 'create':
            flask.request.form.get('username')
            flask.request.form.get('password')
            flask.request.form.get('fullname')
            flask.request.form.get('email')
    
    target_url = flask.request.args.get('target')
    return flask.redirect(target_url)
