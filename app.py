# Project Imports
from flask import Flask
import webbrowser

# Defining Flask App
app = Flask(__name__)

# Instanciates the Flask server and opens the dashboard automatically on localhost
if __name__ == "__main__":
    webbrowser.open_new("http://127.0.0.1:5000/home")
    app.run(debug=False)