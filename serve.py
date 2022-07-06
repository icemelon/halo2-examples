# serve.py

from flask import Flask
from flask import render_template
from flask import make_response
from flask import send_from_directory


# creates a Flask application, named app
app = Flask(__name__, 
            static_url_path='', 
            static_folder='pkg',)

# a route where we will display a welcome message via an HTML template
@app.route("/")
def hello():
    resp = make_response(render_template('index.html'))
    resp.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    resp.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
#     Cross-Origin-Embedder-Policy: require-corp
# Cross-Origin-Opener-Policy: same-origin
    return resp

@app.route('/pkg/<path:path>')
def send_report(path):
    return send_from_directory('pkg', path)

# run the application
if __name__ == "__main__":
    app.run(debug=True)