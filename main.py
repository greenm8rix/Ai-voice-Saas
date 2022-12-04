import json
import threading
from time import sleep
import time
import uuid
from flask_migrate import Migrate
import os
from flask import (
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
    session,
)
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
from email_otp import *
from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    PasswordField,
    SubmitField,
    SelectField,
    TextAreaField,
    FileField,
)
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from model import LoginModel
import nltk.data
from audiojoiner import concatenate_audio_moviepy
from queue import Queue
from storage import test

tokenizer = nltk.data.load("tokenizers/punkt/english.pickle")
api = Api(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "signin"
from google.cloud import storage

jobs = Queue()
storage_client = storage.Client()
voices_available = (
    "angie",
    "cond_latent_example",
    "deniro",
    "freeman",
    "halle",
    " lj" "pat2",
    "snakes",
    "tom",
    "train_daws",
    "train_dreams",
    "train_grace",
    " train_lescault",
    " weaver",
    "applejack",
    "daniel",
    "emma",
    "geralt",
    "jlaw",
    "mol",
    " pat",
    "rainbow",
    "tim_reynolds",
    "train_atkins",
    "train_dotrice",
    "train_empire",
    "train_kennard",
    "train_mouse",
    "william",
    "random",
    " custom_voice",
)
quality_available = ("ultra_fast", "fast", "standard", "high_quality")


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
    voice = SelectField(
        "",
        choices=(voices_available),
    )

    text_file = TextAreaField(
        "text",
        validators=[InputRequired(), Length(min=8, max=1000)],
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
    low_quality = SelectField(
        "",
        choices=("ultra_fast",),
    )
    other_quality = SelectField(
        "",
        choices=(quality_available),
    )
    Custom_Voice = FileField()


class ValidateForm(FlaskForm):

    Otp = TextAreaField(
        "Otp",
        validators=[InputRequired(), Length(min=9, max=9)],
        render_kw={
            "placeholder": "Enter Your 9 Digit OTP",
            "class": "bordder-[#E9EDF4] w-full rounded-md border bg-[#FCFDFE] py-3 px-5 text-base text-body-color placeholder-[#ACB6BE] outline-none transition focus:border-primary focus-visible:shadow-none",
        },
    )

    submit = SubmitField(
        "send",
        render_kw={
            "class": "bordder-primary w-full cursor-pointer rounded-md border bg-primary py-3 px-5 text-base text-white transition duration-300 ease-in-out hover:shadow-md"
        },
    )


def heavy_func(
    text_file, voice_file, quality="ultra_fast", calculation=0, custom_voice=None
):
    # os.environ["REPLICATE_API_TOKEN"] = "b20bf20c9a8f6d4b5cf4c31cfe56f7647e95654a"
    # model = replicate.models.get("afiaka87/tortoise-tts")
    # version = model.versions.get(
    #     "e9658de4b325863c4fcdc12d94bb7c9b54cbfe351b7ca1b36860008172b91c71"
    # )
    # if custom_voice == None:
    #     output = version.predict(
    #         text=text_file, voice_a=voice_file, preset=quality, cvvp_amount=calculation
    #     )
    # else:
    #     output = version.predict(
    #         text=text_file,
    #         voice_a=voice_file,
    #         preset=quality,
    #         cvvp_amount=calculation,
    #         custom_voice=custom_voice,
    #     )
    print(text_file, voice_file, quality, calculation, custom_voice)
    AiVoiceResource.user_download(
        "https://replicate.delivery/pbxt/sxgbNlGz6qJcHxinpo6l5ttArsrWgcfCnRYgmvhRvqeYEmBQA/tortoise.mp3",
        text_file,
    )


def do_stuff(q):
    while not q.empty():
        value = q.get()
        q.task_done()


class AiVoiceResource(Resource):
    @app.route("/status", methods=["GET"])
    @login_required
    def getStatus():

        if current_user.is_authenticated:
            user = current_user.get_id()
            user_data = (
                db.session.query(LoginModel).filter(LoginModel.id == user).first()
            )
            statusList = {
                "status": user_data.progress,
                "filename": user_data.file_url,
            }
            return json.dumps(statusList)

    @app.route("/privacy")
    def privacypolicy():
        return render_template("privacy&policy.html")

    @app.route("/Tos")
    def Tos():
        return render_template("Tos.html")

    @app.route("/user_download")
    def user_download(Url, text_file):
        normal_string = "".join(ch for ch in text_file if ch.isalnum())
        r = requests.get(Url, allow_redirects=True)
        open(
            f"/tmp/{normal_string}.mp3",
            "wb",
        ).write(r.content)

    @app.route("/dashboard")
    @login_required
    def dashboard():
        x = test(current_user.username)
        return render_template("dashboard.html", data=x)

    @app.route("/")
    @app.route("/index")
    def index():
        return render_template("index.html")

    @app.route("/try", methods=["GET"])
    @login_required
    def trynow():

        if current_user.is_authenticated:
            user = current_user.get_id()
            user_data = (
                db.session.query(LoginModel).filter(LoginModel.id == user).first()
            )
            max_character_count, max_downloads = get_subscription_tier(
                user_data.subscription_tier
            )
            if user_data.downloads > max_downloads:
                return redirect(url_for("pricing"))
        form = TryNow()
        if current_user.is_authenticated and current_user.is_verified == True:
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
                if user.is_verified == True:
                    if bcrypt.check_password_hash(user.password, form.password.data):
                        login_user(user)

                        return redirect(url_for("trynow"))
                    else:
                        return redirect(url_for("signin"))

                else:
                    current_otp = sendEmailVerificationRequest(receiver=user.email)
                    session["current_otp"] = current_otp
                    return redirect(url_for("validate"))
            else:
                return redirect(url_for("signup"))

        return render_template("signin.html", form=form)

    @app.route("/validate", methods=["GET", "POST"])
    def validate():
        form = ValidateForm()
        if form.validate_on_submit():
            current_user_otp = session["current_otp"]
            user_otp = form.Otp.data
            try:
                if int(current_user_otp) == int(user_otp):
                    db.session.commit()
                    return redirect(url_for("signin"))
                else:
                    return redirect(url_for("validate"))
            except:
                return redirect(url_for("validate"))
        return render_template("validate.html", form=form)

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
                subscription_tier="FREE",
                is_verified=False,
                downloads=0,
            )
            current_otp = sendEmailVerificationRequest(receiver=form.email.data)
            session["current_otp"] = current_otp

            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("validate"))

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
        if current_user.is_authenticated and current_user.is_verified == True:
            form = TryNow()
            if form.validate_on_submit:
                text_file = form.text_file.data
                voice_file = form.voice.data
                if current_user.subscription_tier == "FREE":
                    voice_quality = form.low_quality.data
                    custom_voices = None
                    calculation = 0
                else:
                    custom_voices = form.Custom_Voice.data
                    voice_quality = form.other_quality.data
                    calculation = 1

                if current_user.is_authenticated:
                    user = current_user.get_id()
                    user_data = (
                        db.session.query(LoginModel)
                        .filter(LoginModel.id == user)
                        .first()
                    )
                max_character_count, max_downloads = get_subscription_tier(
                    user_data.subscription_tier
                )
                character_count = 0
                for characters in text_file:
                    character_count += 1
                if character_count > max_character_count:
                    return redirect(url_for("pricing"))
                if user_data.downloads > max_downloads:
                    return redirect(url_for("pricing"))

                splitting_into_smaller = tokenizer.tokenize(text_file)
                number = []
                threads = []
                for i in splitting_into_smaller:
                    normal_string = "".join(ch for ch in i if ch.isalnum())
                    number.append(normal_string)
                    jobs.put(
                        heavy_func(
                            i,
                            voice_file,
                            quality=voice_quality,
                            calculation=calculation,
                            custom_voice=custom_voices,
                        )
                    )

                for i in range(3):
                    worker = threading.Thread(target=do_stuff, args=(jobs,))
                    threads.append(worker)
                    worker.start()
                file_name = user_data.username + str(user_data.downloads)
                username = user_data.username
                threading.Thread(
                    target=concatenate_audio_moviepy,
                    args=(number, jobs, file_name, username),
                ).start()
                user_data.downloads += 1
                db.session.commit()
                return redirect(url_for("dashboard"))
            return redirect(url_for("validate"))


api.add_resource(AiVoiceResource)
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="127.0.0.1", port=8080, debug=True, threaded=True)
