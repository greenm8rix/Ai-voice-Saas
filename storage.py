from google.cloud import storage

GOOGLE_APPLICATION_CREDENTIALS = r"C:\Users\nawaf\Desktop\ExalioDevelopment\Ai voice Saas\application_default_credentials.json"


def create_folder(bucket_name, destination_folder_name):
    storage_client = storage.Client()

    buckets = list(storage_client.list_buckets())

    bucket = storage_client.get_bucket(bucket_name)  # your bucket name

    blob = bucket.blob(f"{destination_folder_name}/output")
    blob.upload_from_filename(
        r"C:\Users\nawaf\Desktop\ExalioDevelopment\Ai voice Saas\audios\output.mp3"
    )
    print(buckets)


folder = create_folder("user_files_for_bravo", "test-folder")
