import json
from random import randint
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
from werkzeug.utils import secure_filename
import replicate
from flask_restful import Resource, Api
import requests
from calculator import get_subscription_tier
from config import db, app
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
from model import LoginModel, products, StripeCustomer
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
import stripe

jobs = Queue()
storage_client = storage.Client()
voices_available = (
    "angie",
    "cond_latent_example",
    "deniro",
    "freeman",
    "halle",
    "lj",
    "pat2",
    "snakes",
    "tom",
    "train_daws",
    "train_dreams",
    "train_grace",
    "train_lescault",
    "weaver",
    "applejack",
    "daniel",
    "emma",
    "geralt",
    "jlaw",
    "mol",
    "pat",
    "rainbow",
    "tim_reynolds",
    "train_atkins",
    "train_dotrice",
    "train_empire",
    "train_kennard",
    "train_mouse",
    "william",
)
quality_available = ("ultra_fast", "fast", "standard")
secret_key = os.environ.get("STRIPE_SECRET_KEY")
publishable_key = os.environ.get("STRIPE_PUBLISHABLE_KEY")
price_id = os.environ.get("STRIPE_PRICE_ID")
price_id1 = os.environ.get("STRIPE_PRICE_ID1")
endpoint_secret = os.environ.get("STRIPE_ENDPOINT_SECRET")
stripe_keys = {
    "secret_key": secret_key,
    "publishable_key": publishable_key,
    "price_id": price_id,
    "endpoint_secret": endpoint_secret,
    "price_id1": price_id1,
}
stripe.api_key = stripe_keys["secret_key"]


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
        validators=[InputRequired(), Length(min=4, max=40)],
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


class accountform(FlaskForm):

    submit = SubmitField(
        "Manage Billing",
        render_kw={
            "class": "inline-flex items-center justify-center rounded-lg bg-blue py-4 px-6 text-center text-base font-medium text-dark transition duration-300 ease-in-out hover:text-primary hover:shadow-lg sm:px-10"
        },
    )


def heavy_func(
    text_file, voice_file, quality="ultra_fast", calculation=0, custom_voice=None
):
    os.environ["REPLICATE_API_TOKEN"]
    model = replicate.models.get("afiaka87/tortoise-tts")
    version = model.versions.get(
        "e9658de4b325863c4fcdc12d94bb7c9b54cbfe351b7ca1b36860008172b91c71"
    )
    if custom_voice == None:
        output = version.predict(
            text=text_file,
            voice_a=voice_file,
            preset=quality,
            cvvp_amount=calculation,
            seed=4532,
        )
    else:
        output = version.predict(
            text=text_file,
            voice_a=voice_file,
            preset=quality,
            cvvp_amount=calculation,
            custom_voice=custom_voice,
            seed=4532,
        )
    AiVoiceResource.user_download(
        output,
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

    @app.route("/success")
    def success():
        return render_template("success.html")

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
        if current_user.is_authenticated:
            context = current_user.subscription_tier
            return render_template("index.html", context=context)
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
            if user_data.downloads >= max_downloads:
                return redirect(url_for("pricing"))
        form = TryNow()
        if current_user.is_authenticated and current_user.is_verified == True:
            return render_template("try.html", form=form)
        else:
            return redirect(url_for("signin"))

    @app.route("/signin", methods=["GET", "POST"])
    def signin():
        if current_user.is_authenticated:
            return redirect(url_for("index"))

        form = LoginForm()
        if form.validate_on_submit():
            user = (
                db.session.query(LoginModel)
                .filter(LoginModel.username == form.username.data)
                .first()
            )
            if not user:
                user = (
                    db.session.query(LoginModel)
                    .filter(LoginModel.email == form.username.data)
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
                    session["username"] = form.username.data
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
            username = session["username"]
            user = (
                db.session.query(LoginModel)
                .filter(LoginModel.username == username)
                .first()
            )
            if not user:
                user = (
                    db.session.query(LoginModel)
                    .filter(LoginModel.email == username)
                    .first()
                )

            if user:
                if int(current_user_otp) == int(user_otp):
                    user.is_verified = True
                    db.session.commit()
                    return redirect(url_for("signin"))
                else:
                    return redirect(url_for("validate"))
            else:
                redirect(url_for("signup"))
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
            session["username"] = form.username.data

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

    @app.route("/config")
    def get_publishable_key():
        stripe_config = {"publicKey": stripe_keys["publishable_key"]}
        return jsonify(stripe_config)

    @app.route("/howto")
    def HowTo():
        return render_template("howto.html")

    @app.route("/create-checkout-session")
    def create_checkout_session():
        domain_url = "https://bravovoice.in/"
        stripe.api_key = stripe_keys["secret_key"]

        try:
            checkout_session = stripe.checkout.Session.create(
                success_url=domain_url + "success?session_id={CHECKOUT_SESSION_ID}",
                cancel_url=domain_url + "index",
                payment_method_types=["card"],
                mode="subscription",
                client_reference_id=current_user.id,
                line_items=[
                    {
                        "price": stripe_keys["price_id"],
                        "quantity": 1,
                    }
                ],
            )
            user = (
                db.session.query(LoginModel)
                .filter(LoginModel.id == current_user.id)
                .first()
            )
            user.progress = stripe_keys["price_id"]
            db.session.commit()
            return jsonify({"sessionId": checkout_session["id"]})
        except Exception as e:
            return jsonify(error=str(e)), 403

    @app.route("/create-checkout-sessions")
    def create_checkout_sessions():
        domain_url = "https://bravovoice.in/"
        stripe.api_key = stripe_keys["secret_key"]

        try:
            checkout_session = stripe.checkout.Session.create(
                success_url=domain_url + "success?session_id={CHECKOUT_SESSION_ID}",
                cancel_url=domain_url + "index",
                payment_method_types=["card"],
                mode="subscription",
                client_reference_id=current_user.id,
                line_items=[
                    {
                        "price": stripe_keys["price_id1"],
                        "quantity": 1,
                    }
                ],
            )
            user = (
                db.session.query(LoginModel)
                .filter(LoginModel.id == current_user.id)
                .first()
            )
            user.progress = stripe_keys["price_id1"]
            db.session.commit()
            return jsonify({"sessionId": checkout_session["id"]})
        except Exception as e:
            return jsonify(error=str(e)), 403

    @app.route("/webhook", methods=["POST"])
    def stripe_webhook():
        payload = request.get_data(as_text=True)
        sig_header = request.headers.get("Stripe-Signature")

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, stripe_keys["endpoint_secret"]
            )

        except ValueError as e:
            # Invalid payload
            return "Invalid payload", 400
        except stripe.error.SignatureVerificationError as e:
            # Invalid signature
            return "Invalid signature", 400

        # Handle the checkout.session.completed event
        if event["type"] == "checkout.session.completed":
            session = event["data"]["object"]

            # Fulfill the purchase...
            AiVoiceResource.handle_checkout_session(session)
        if event["type"] == "customer.subscription.deleted":
            session = event["data"]["object"]
            AiVoiceResource.handle_checkout_session(session)

        return "Success", 200

    def handle_checkout_session(session):
        user_data = (
            db.session.query(LoginModel)
            .filter(LoginModel.id == session["client_reference_id"])
            .first()
        )
        product_data = (
            db.session.query(products)
            .filter(products.price_id == user_data.progress)
            .first()
        )
        stripe_user = (
            db.session.query(StripeCustomer)
            .filter(
                StripeCustomer.user_id == session["client_reference_id"],
            )
            .first()
        )
        if not stripe_user:
            new_user = StripeCustomer(
                stripeCustomerId=session["customer"],
                stripeSubscriptionId=session["subscription"],
                user_id=session["client_reference_id"],
            )
            db.session.add(new_user)
        else:
            if stripe_user:
                subscription = stripe.Subscription.retrieve(
                    stripe_user.stripeSubscriptionId
                )
                stripe.Subscription.modify(subscription.id, cancel_at_period_end=True)
            stripe_user.stripeCustomerId = (session["customer"],)
            stripe_user.stripeSubscriptionId = session["subscription"]

        user_data.subscription_tier = product_data.Product
        user_data.downloads = 0

        db.session.commit()

    @app.route("/account", methods=["GET"])
    @login_required
    def account():
        form = accountform()
        return render_template("account.html", form=form)

    @app.route("/account", methods=["POST"])
    @login_required
    def manage():
        form = accountform()
        if form.validate_on_submit:
            stripe.api_key = stripe_keys["secret_key"]
            stripe.billing_portal.Configuration.create(
                business_profile={
                    "headline": "Bravo partners with Stripe for simplified billing.",
                },
                features={"invoice_history": {"enabled": True}},
            )
            stripe_user = (
                db.session.query(StripeCustomer).filter(
                    StripeCustomer.user_id == current_user.id,
                )
            ).first()

            if not stripe_user:
                return redirect("pricing")
            session = stripe.billing_portal.Session.create(
                customer=stripe_user.stripeCustomerId,
                return_url="https://bravovoice.in/account",
            )

        return redirect(session.url)

    @app.route("/try", methods=["POST"])
    @login_required
    def ai_voice():
        if current_user.is_authenticated and current_user.is_verified == True:
            user = current_user.get_id()
            user_data = (
                db.session.query(LoginModel).filter(LoginModel.id == user).first()
            )
            form = TryNow()
            customer = StripeCustomer.query.filter_by(user_id=current_user.id).first()
            if customer:
                subscription = stripe.Subscription.retrieve(
                    customer.stripeSubscriptionId
                )
                if subscription.status != "active":
                    return redirect(url_for("pricing"))
            max_character_count, max_downloads = get_subscription_tier(
                user_data.subscription_tier
            )
            character_count = 0

            if user_data.downloads >= max_downloads:
                return redirect(url_for("pricing"))
            if form.validate_on_submit:
                text_file = form.text_file.data
                voice_file = form.voice.data
                for characters in text_file:
                    character_count += 1
                if character_count > max_character_count:
                    return redirect(url_for("pricing"))
                if current_user.subscription_tier == "FREE":
                    voice_quality = form.low_quality.data
                    custom_voices = None
                    calculation = 0
                else:

                    if form.Custom_Voice.data.filename == "":
                        custom_voices, blob = None, None
                    else:

                        form.Custom_Voice.data.save(
                            os.path.join(
                                "/tmp", secure_filename(form.Custom_Voice.data.filename)
                            )
                        )
                        from storage import create_folder_tmp

                        custom_voices, blob = create_folder_tmp(
                            current_user.username,
                            os.path.join(
                                "/tmp", secure_filename(form.Custom_Voice.data.filename)
                            ),
                            form.Custom_Voice.data.filename,
                        )

                    voice_quality = form.other_quality.data
                    calculation = 0.70
                splitting_into_smaller = tokenizer.tokenize(text_file)
                number = []
                threads = []
                for i in splitting_into_smaller:
                    normal_string = "".join(ch for ch in i if ch.isalnum())
                    number.append(normal_string)
                    j = threading.Thread(
                        target=heavy_func,
                        args=(i, voice_file, voice_quality, calculation, custom_voices),
                    )
                    threads.append(j)

                for x in threads:
                    x.start()
                file_name = user_data.username + str(user_data.downloads)
                username = user_data.username
                threading.Thread(
                    target=concatenate_audio_moviepy,
                    args=(number, threads, file_name, username, blob),
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
