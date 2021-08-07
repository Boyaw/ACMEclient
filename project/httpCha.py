from flask import Flask, Response
app = Flask(__name__)


@app.route('/hello', methods = ['GET'])
def api_hello():
    data = {
        'hello'  : 'world',
        'number' : 3
    }
    js = json.dumps(data)

    resp = Response(js, status=200, mimetype='application/json')

    return resp


if __name__ == "__main__":
    app.run(port=5002, debug=True, host='0.0.0.0')