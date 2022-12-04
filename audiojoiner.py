import os
from moviepy.editor import concatenate_audioclips, AudioFileClip
from config import db, app
from model import LoginModel
from storage import create_folder


def concatenate_audio_moviepy(number, jobs, username, name):
    with app.app_context():
        user_data = (
            db.session.query(LoginModel).filter(LoginModel.username == name).first()
        )
        output_path = f"/tmp/{username}.mp3"
        user_data.progress = "in_progress"
        db.session.commit()
        print("waiting for queue to complete", jobs.qsize(), "tasks")
        jobs.join()
        print("all done")
        dirs = os.listdir("/tmp")
        if len(dirs) > 0:
            """Concatenates several audio files into one audio file using MoviePy
            and save it to `output_path`. Note that extension (mp3, etc.) must be added to `output_path`"""
            audios = []
            for j in number:
                for x in dirs:
                    if j + ".mp3" == x:
                        audios.append(AudioFileClip(f"/tmp/{x}"))

            final_clip = concatenate_audioclips([audio for audio in audios])
            final_clip.write_audiofile(output_path)
            destination_folder = user_data.username + str(user_data.downloads) + ".mp3"

            url = create_folder(
                username=user_data.username,
                filename=output_path,
                username_downloads=destination_folder,
            )
            user_data.file_url = url
            user_data.progress = "Done."
            db.session.commit()
            os.remove(output_path)
            for j in number:
                for x in dirs:
                    if j + ".mp3" == x:

                        os.remove(f"tmp/{x}")
