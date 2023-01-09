import os
from urllib import response
import openai
import config

openai.api_key = config.OPENAI_API_KEY
from config import db, app
from model import LoginModel
from calculator import get_subscription_tier_content


def aicontent(query, user):
    user_data = db.session.query(LoginModel).filter(LoginModel.id == user).first()
    max_downloads = get_subscription_tier_content(user_data.subscription_tier_content)
    if max_downloads < user_data.downloads_content:
        return "exceeded"
    response = openai.Completion.create(
        engine="text-davinci-003",
        prompt=query,
        temperature=0.8,
        max_tokens=256,
        top_p=1,
        frequency_penalty=0,
        presence_penalty=0,
    )

    if "choices" in response:
        if len(response["choices"]) > 0:
            answer = response["choices"][0]["text"]
            user_data.downloads_content += 1
            db.session.commit()
        else:
            answer = "Ugh oh ! i accept i fail !"
    return answer
