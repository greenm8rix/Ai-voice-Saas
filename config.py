import os
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
import os
import sqlalchemy
from google.cloud.sql.connector import Connector, IPTypes
import pg8000

db_user = os.environ.get("CLOUD_SQL_USERNAME")
db_password = os.environ.get("CLOUD_SQL_PASSWORD")
db_name = os.environ.get("CLOUD_SQL_DATABASE_NAME")
db_connection_name = os.environ.get("CLOUD_SQL_CONNECTION_NAME")
app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
)

# app.config[
#     "SQLALCHEMY_DATABASE_URI"
# ] = "postgresql://postgres:postgres@localhost:5432/bravo_api"
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = f"postgresql://{db_user}:{db_password}@/{db_name}?host=/cloudsql/{db_connection_name}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "thisisasecretkey"
db = SQLAlchemy(app)
