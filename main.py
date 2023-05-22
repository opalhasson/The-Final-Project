from flask import Flask, render_template, request
from NVDsearch import NVDsearch

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('homePage.html')

@app.route('/scan', methods=['POST'])
def scan():
    os = request.form.get('os')
    print(os)
    NVDsearch(os)
    return render_template('reportPage.html')

def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

@app.route('/shutdown', methods=['GET'])
def shutdown():
    shutdown_server()
    return 'Server shutting down...'

if __name__ == '__main__':
    app.run()
