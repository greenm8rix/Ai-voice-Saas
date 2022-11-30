import os
from google.cloud import storage

full_path = os.path.realpath(__file__)
GOOGLE_APPLICATION_CREDENTIALS = (
    os.path.dirname(full_path) + "application_default_credentials.json"
)


def create_folder(
    username,
    filename,
    username_downloads,
    bucket_name="user_files_for_bravo",
):
    storage_client = storage.Client()

    buckets = list(storage_client.list_buckets())

    bucket = storage_client.get_bucket(bucket_name)  # your bucket name

    blob = bucket.blob(f"{username}/{username_downloads}")
    blob.upload_from_filename(filename)
    blob.make_public()
    return blob.public_url
