import json
import threading
from time import sleep
import uuid
from flask_migrate import Migrate
import os
from flask import flash, jsonify, redirect, render_template, request, send_file, url_for
import replicate
from flask_restful import Resource, Api
import requests
from calculator import get_subscription_tier
from config import db, app
import concurrent
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    login_required,
    logout_user,
    current_user,
)
from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    PasswordField,
    SubmitField,
    SelectField,
    TextAreaField,
)
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from model import LoginModel
import nltk.data
from audiojoiner import concatenate_audio_moviepy
from queue import Queue

nltk.download("punkt")
tokenizer = nltk.data.load("tokenizers/punkt/english.pickle")
api = Api(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "signin"


jobs = Queue()


@login_manager.user_loader
def load_user(user_id):
    return LoginModel.query.get((user_id))


class RegisterForm(FlaskForm):
    email = StringField(
        validators=[InputRequired(), Length(min=4, max=40)],
        render_kw={
            "placeholder": "Email",
            "type": "email",
            "class": "bordder-[#E9EDF4] w-full rounded-md border bg-[#FCFDFE] py-3 px-5 text-base text-body-color placeholder-[#ACB6BE] outline-none transition focus:border-primary focus-visible:shadow-none",
        },
    )

    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={
            "placeholder": "Username",
            "class": "bordder-[#E9EDF4] w-full rounded-md border bg-[#FCFDFE] py-3 px-5 text-base text-body-color placeholder-[#ACB6BE] outline-none transition focus:border-primary focus-visible:shadow-none",
        },
    )

    password = PasswordField(
        validators=[InputRequired(), Length(min=8, max=20)],
        render_kw={
            "placeholder": "Password",
            "class": "bordder-[#E9EDF4] w-full rounded-md border bg-[#FCFDFE] py-3 px-5 text-base text-body-color placeholder-[#ACB6BE] outline-none transition focus:border-primary focus-visible:shadow-none",
        },
    )

    submit = SubmitField(
        "Register",
        render_kw={
            "class": "bordder-primary w-full cursor-pointer rounded-md border bg-primary py-3 px-5 text-base text-white transition duration-300 ease-in-out hover:shadow-md"
        },
    )

    def validate_username(self, username):
        existing_user_username = (
            db.session.query(LoginModel)
            .filter(LoginModel.username == username.data)
            .first()
        )
        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a different one."
            )

    def validate_email(self, email):
        existing_user_email = (
            db.session.query(LoginModel).filter(LoginModel.email == email.data).first()
        )
        if existing_user_email:
            raise ValidationError(
                "That email already exists. Please choose a different one."
            )


class LoginForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={
            "placeholder": "Username",
            "class": "bordder-[#E9EDF4] w-full rounded-md border bg-[#FCFDFE] py-3 px-5 text-base text-body-color placeholder-[#ACB6BE] outline-none transition focus:border-primary focus-visible:shadow-none",
        },
    )

    password = PasswordField(
        validators=[InputRequired(), Length(min=8, max=20)],
        render_kw={
            "placeholder": "Password",
            "class": "bordder-[#E9EDF4] w-full rounded-md border bg-[#FCFDFE] py-3 px-5 text-base text-body-color placeholder-[#ACB6BE] outline-none transition focus:border-primary focus-visible:shadow-none",
        },
    )

    submit = SubmitField(
        "Login",
        render_kw={
            "class": "bordder-primary w-full cursor-pointer rounded-md border bg-primary py-3 px-5 text-base text-white transition duration-300 ease-in-out hover:shadow-md"
        },
    )


class TryNow(FlaskForm):
    voice = SelectField("", choices=("angie", "freeman", "deniro", "halle", "random"))

    text_file = TextAreaField(
        "text",
        validators=[InputRequired(), Length(min=8, max=3000)],
        render_kw={
            "placeholder": "Enter Your Text(50) Characters",
            "class": "bordder-[#E9EDF4] w-full rounded-md border bg-[#FCFDFE] py-3 px-5 text-base text-body-color placeholder-[#ACB6BE] outline-none transition focus:border-primary focus-visible:shadow-none",
        },
    )

    submit = SubmitField(
        "send",
        render_kw={
            "class": "bordder-primary w-full cursor-pointer rounded-md border bg-primary py-3 px-5 text-base text-white transition duration-300 ease-in-out hover:shadow-md"
        },
    )

    def validate_text(self, text_file):
        print(text_file)
        if current_user.is_authenticated:
            user = current_user.get_id()
            user_data = (
                db.session.query(LoginModel).filter(LoginModel.id == user).first()
            )
        max_character_count, max_downloads = get_subscription_tier(
            user_data.subscription_tier
        )


def heavy_func(q, version, text_file, voice_file):
    while not q.empty():
        value = q.get()
        # output = version.predict(
        #     text=text_file, voice_a=voice_file, preset="high_quality", cvvp_amount=1
        # )

        AiVoiceResource.user_download(
            "https://replicate.delivery/pbxt/sxgbNlGz6qJcHxinpo6l5ttArsrWgcfCnRYgmvhRvqeYEmBQA/tortoise.mp3",
            text_file,
        )
        q.task_done()


class AiVoiceResource(Resource):
    @app.route("/privacy")
    def privacypolicy():
        return redirect("https://merchant.razorpay.com/policy/KkN3ZDoj8H88D6/privacy")

    @app.route("/user_download")
    def user_download(Url, text_file):
        normal_string = "".join(ch for ch in text_file if ch.isalnum())
        r = requests.get(Url, allow_redirects=True)
        open(
            f"/tmp/{normal_string}.mp3",
            "wb",
        ).write(r.content)

    @app.route("/")
    @app.route("/index")
    def index():
        return render_template("index.html")

    @login_required
    @app.route("/try", methods=["GET"])
    def trynow():
        form = TryNow()
        if current_user.is_authenticated:
            return render_template("try.html", form=form)
        else:
            return redirect(url_for("signin"))

    @app.route("/signin", methods=["GET", "POST"])
    def signin():
        form = LoginForm()
        if form.validate_on_submit():
            user = (
                db.session.query(LoginModel)
                .filter(LoginModel.username == form.username.data)
                .first()
            )
            if user:
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)

                    return redirect(url_for("trynow"))

        return render_template("signin.html", form=form)

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        form = RegisterForm()
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
                "utf-8"
            )
            new_user = LoginModel(
                id=uuid.uuid4(),
                email=form.email.data,
                username=form.username.data,
                password=hashed_password,
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("signin"))

        return render_template("signup.html", form=form)

    @app.route("/logout", methods=["GET", "POST"])
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("signin"))

    @app.route("/pricing")
    def pricing():
        return render_template("pricing.html")

    @app.route("/contact")
    def contact():
        return render_template("contact.html")

    @app.route("/Examples")
    def example():
        return render_template("examples.html")

    @app.route("/try", methods=["POST"])
    @login_required
    def ai_voice():
        form = TryNow()
        for i in range(5):
            jobs.put(i)
        if form.validate_on_submit:
            text_file = form.text_file.data
            if current_user.is_authenticated:
                user = current_user.get_id()
                user_data = (
                    db.session.query(LoginModel).filter(LoginModel.id == user).first()
                )
            max_character_count, max_downloads = get_subscription_tier(
                user_data.subscription_tier
            )
            character_count = 0
            for characters in text_file:
                character_count += 1
            if character_count > max_character_count:
                raise ValidationError(
                    f"please Reduce the character count from {character_count} or Upgrade From {user_data.subscription_tier} tier to increase character count"
                )
            if user_data.downloads < max_downloads:
                raise ValidationError(
                    f"please Upgrade From {user_data.subscription_tier} tier to increase download count"
                )
            voice_file = request.form["voice"]
            os.environ[
                "REPLICATE_API_TOKEN"
            ] = "b20bf20c9a8f6d4b5cf4c31cfe56f7647e95654a"
            model = replicate.models.get("afiaka87/tortoise-tts")
            version = model.versions.get(
                "e9658de4b325863c4fcdc12d94bb7c9b54cbfe351b7ca1b36860008172b91c71"
            )
            splitting_into_smaller = tokenizer.tokenize(text_file)
            number = []
            threads = []
            for i in splitting_into_smaller:
                normal_string = "".join(ch for ch in i if ch.isalnum())
                number.append(normal_string)
                j = threading.Thread(
                    target=heavy_func, args=(jobs, version, i, voice_file)
                )
                threads.append(j)
                # with concurrent.futures.ThreadPoolExecutor(8) as executor:
                #     future = executor.submit(heavy_func, version, i, voice_file)

            for x in threads:
                x.start()
            h = threading.active_count()
            print(h)
            for x in threads:
                x.join()
            concatenate_audio_moviepy(number)
            user_data.downloads += 1
            db.session.commit()
            return send_file("/tmp/output.mp3", as_attachment=True)


api.add_resource(AiVoiceResource)
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="127.0.0.1", port=8080, debug=True, threaded=True)
