import os
from flask import jsonify
from google.cloud import storage

GOOGLE_APPLICATION_CREDENTIALS = "./application_default_credentials.json"

storage_client = storage.Client()
from py_topping.data_connection.gcp import lazy_GCS

gcs = lazy_GCS(
    project_id="bravo-ai-voice",
    bucket_name="user_files_for_bravo",
    credential=GOOGLE_APPLICATION_CREDENTIALS,
)


def create_folder(
    username,
    filename,
    username_downloads,
    bucket_name="user_files_for_bravo",
):

    bucket = storage_client.get_bucket(bucket_name)  # your bucket name

    blob = bucket.blob(f"{username}/{username_downloads}")
    blob.upload_from_filename(filename)
    blob.make_public()
    return blob.public_url


def test(username):
    j = gcs.list_folder(
        bucket_folder=username,
        as_blob=False,  # If False : return as name
        include_self=False,  # If True : also return bucket_folder
        get_file=True,  # Get files in a list or not
        get_folder=False,  # Get Folder in a list or not, not include bucket_folder
        all_file=False,  # If True : Will get all files from folder and sub-folder(s)
    )
    bucket = storage_client.get_bucket("user_files_for_bravo")

    l = []  # your bucket name
    for i in j:
        blob = bucket.blob(f"{i}")
        l.append(blob.public_url)
    return l
