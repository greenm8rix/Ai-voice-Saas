import random
import smtplib


def generateOTP(otp_size=9):
    final_otp = ""
    for i in range(otp_size):
        final_otp = final_otp + str(random.randint(0, 9))
    return final_otp


def sendEmailVerificationRequest(
    sender="exaliodevelopment@gmail.com",
    receiver="nawafsheikh10@gmail.com@gmail.com",
    custom_text="Hello, Your OTP From Bravo is ",
):
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    google_app_password = "nppzynekmvqxhojh"
    server.login(sender, google_app_password)
    cur_otp = generateOTP()
    msg = custom_text + cur_otp
    server.sendmail(sender, receiver, msg)
    server.quit()
    return cur_otp
