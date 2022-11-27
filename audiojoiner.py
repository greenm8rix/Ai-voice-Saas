import os
from moviepy.editor import concatenate_audioclips, AudioFileClip


dir = os.listdir("tmp/records/")


def concatenate_audio_moviepy(
    number,
    output_path="tmp/audios/output.mp3",
):
    if len(dir) > 0:
        """Concatenates several audio files into one audio file using MoviePy
        and save it to `output_path`. Note that extension (mp3, etc.) must be added to `output_path`"""
        audios = []
        for j in number:
            for x in dir:
                if j + ".mp3" == x:
                    audios.append(AudioFileClip(f"tmp/records/{x}"))
        final_clip = concatenate_audioclips([audio for audio in audios])
        final_clip.write_audiofile(output_path)
