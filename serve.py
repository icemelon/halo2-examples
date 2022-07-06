# serve.py

from flask import Flask
from flask import render_template
from flask import make_response

# creates a Flask application, named app
app = Flask(__name__)

# a route where we will display a welcome message via an HTML template
@app.route("/")
def hello():
    resp = make_response(render_template('index.html'))
    resp.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    resp.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
#     Cross-Origin-Embedder-Policy: require-corp
# Cross-Origin-Opener-Policy: same-origin
    return resp

# run the application
if __name__ == "__main__":
    app.run(debug=True)