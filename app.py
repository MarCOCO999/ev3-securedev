from flask import Flask, request
from monitoring import init_monitoring

app = Flask(__name__)
init_monitoring(app)


@app.route('/hello')
def hello():
    name = request.args.get('name')
    return f"Hello, {name}!"


if __name__ == '__main__':
    # host='0.0.0.0' solo para que el contenedor sea accesible desde la red de Docker.
    app.run(host='0.0.0.0', debug=True)
