#!!!!!!!!!!!!!!!!!!!!!!!!!! START !!!!!!!!!!!!!!!!!!!!!!!!!!

#importing flask and flask cors to establish a secure connection between front end and backend services.
######################################################################################################
#going private

from pytz import timezone 
from datetime import datetime
from flask import Flask, request
import pymongo
from bson import ObjectId
from flask_cors import CORS, cross_origin
from email.message import EmailMessage
import smtplib
import base64
import random
from dotenv import load_dotenv
import os
import json
import string
import secrets

load_dotenv()
credentials = os.environ.get
#embedding credentials securely to deliver on api calls.
sender_email = credentials["sender_email"]
password = credentials["password"]
blocked = credentials["blocked"]
connection_sent = credentials["connection_sent"]
req_origin = credentials["origins"]




#defining our app as a Flask application
app = Flask(__name__)


CORS(app)

#Setting up out frontend service address to be allowed by CORS policy
origin = {
    "origins":req_origin
}
cors = CORS(app, resources={"*": origin})
app.config['CORS_HEADERS'] = 'Content-Type'


@app.route('/')
def return_alive():
    return "ALIVE BITCH"


#~~~~~~~~~~~~~~~~~~~~~~~FUNCTIONS~~~~~~~~~~~~~~~~~~~~~~~#

#a function for encrypting passwords or other strings on base64
def encryptpassword(password):
    pas= password.encode("utf-8") #encoding in utf-8 format before encoding in base64
    encodedpassword = base64.b64encode(pas) #encoding in base64
    return encodedpassword #returns the encoded value to function





#a function for decrypting passwords or other strings on base64
def decryptpassword(password):
    password = base64.b64decode(password) #decoding in base64
    decodedpassword = password.decode("utf-8") #decoding in utf-8 format before encoding in base64
    return decodedpassword #returns the decoded value to function





#a function for sending otp to user
def sendotp(mail, otp):
    subject = "OTP Received" #subject of the mail
    body = "Hello! This is your OTP - " + otp + ".\n Please do not share it with anyone. It is valid for 3 minutes." #body of the mail
    msg = EmailMessage() #calling object to assign subject and body
    msg["Subject"] = subject
    msg["From"] = sender_email #getting from credentials
    msg["To"] = mail #getting from function call
    msg.set_content(body)
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(sender_email, password) #getting from credentials
        smtp.send_message(msg) #sending message through SMTP_SSL





#a function for generating random number strings to use as session variable
def limlog(n):
    res = ''.join(secrets.choice(string.ascii_uppercase + string.digits)
                                                    for i in range(n))
    return res

@app.route('/', methods=['GET'])
def alive():
    return "Sup?"



#~~~~~~~~~~~~~~~~~~~~~~~SUPER-ADMIN-APIS~~~~~~~~~~~~~~~~~~~~~~~

#api for creating new superadmin
@app.route('/supernew', methods=['POST'])
def supernew():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    sdetails = railwaydb["superadmin"]
    sname = request.json["sname"]
    sadmin = request.json["sid"]
    spass = request.json["spass"]
    smail = request.json["smail"]
    firstocc = 0
    firstdot = 0
    emailvalid = False
    saveatpoint = len(smail) + 1
    for i in range(len(smail)):
        if smail[i] == "@" and i!=0:
            if firstocc == 0:
                saveatpoint = i
            firstocc = firstocc + 1
        if i > saveatpoint and smail[i] == ".":
            firstdot = firstdot + 1
    if firstocc == 1 and firstdot == 1  and smail[0] != "@" and smail[len(smail) - 1] != "." and smail[len(smail) - 1] != "@":
        emailvalid = True
    if sname == "":
        return 'ERROR- NO NAME'
    elif sadmin == "":
        return 'ERROR- NO ID'
    elif len(spass) < 8:
        return 'PASS  LESS_8'
    elif emailvalid == False:
        return 'INVALID_EMAIL'
    else:
        superflagid = sdetails.find_one({"super_aid":sadmin})
        superflagemail = sdetails.find_one({"smail":smail})
        if superflagid != None:
            return "USERNAME EXISTS"
        elif superflagemail != None:
            return "EMAIL EXISTS"
        else:
            spass = encryptpassword(spass)
            sdetails.insert_one({"super_admin":sname, "super_apass":spass, "super_aid":sadmin, "smail":smail, "myotp":"", "lastlog":"", "session":"" })
            return "Data Inserted Successfully"






#api for generating and sending OTP to superadmin after successfull pushing of credentials
@app.route('/superadminotp', methods=['POST'])
def superadminlockotp():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    sdetails = railwaydb["superadmin"] #pointing to superadmin collection
    myotp = random.randint(100000,999999) #generating random 6 digit value
    myotp = str(myotp) 
    smyotp = myotp
    myotp = encryptpassword(myotp) #encrypting otp for database store
    mypass = request.json["spass"]
    mypass = encryptpassword(mypass) #encrypting password for database store
    superadmin = sdetails.find_one({"super_aid":request.json["sid"], "super_apass":mypass}) #searching for superadmin with entered credetials
    if request.json["sid"] == "": #checking the veracity
        return "username is needed"
    elif request.json["spass"] == "": #checking the veracity
        return "password is needed"
    elif superadmin == None: #checking if superadmin exists supporting the entered credentials or not
        return "invalid username or password"
    else: #if exists
        sdetails.update_one({"super_aid":request.json["sid"], "super_apass":mypass}, {"$set":{"myotp":myotp}}) #setting the generated otp to document for further checking
        myotp = smyotp
        sendotp(superadmin["smail"], myotp) #calling send otp to send the user the copy of otp over mail.
        return "OTP sent to registered email id and valid for only 3 minutes."





#api for checking if current session of superadmin is valid or not
@app.route('/returnpasssuper', methods=['POST'])
def returnpasssuper():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    adetails = railwaydb["superadmin"] #pointing to superadmin collection
    ifuser = adetails.find_one({"super_aid":request.json["sid"], "session":request.json["session"]}) #finding superadmin supporting the session
    if ifuser != None: #validating the session
        return "success"
    else:
        return "no session"





#api for checking the OTP of superadmin and successfully creating a session and saving info to DB
@app.route('/superadminlock', methods=['POST'])
def superadminlockdb():
    flagtime = datetime.now(timezone("Asia/Kolkata")) #getting current time flag
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    adetails = railwaydb["superadmin"] #pointing to superadmin collection
    superpass = request.json["spass"]
    superpass = encryptpassword(superpass) #encrypting password to checkin with database
    myotp = request.json["otp"]
    myotp = encryptpassword(myotp) #encrypting otp to checkin with database
    inp = adetails.find_one({"super_aid":request.json["sid"], "super_apass": superpass, "myotp":myotp}) #checking if the otp is valid or not
    if request.json["otp"] == "": #checking the veracity
        return "Please enter OTP."
    else:
        if inp == None: #if otp not valid
            return "incorrect credentials"
        else: #else generate a 20 characters long session variable to store and approve login
            var = limlog(20) #generating the 20 character long session variable
            adetails.update_one({"super_aid":request.json["sid"], "super_apass":superpass}, {"$set":{"lastlog":str(flagtime) ,"myotp":"", "session":var}}) #flagging the log in time, clearing the myotp section to invalidate the old otp, setting the session to document for further login.
            #sending an alert to Database Administrator
            subject = "SuperAdmin Logged In"
            body = "SuperAdmin - '" + inp["super_admin"] + "' just logged in."
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = sender_email
            msg["To"] = "luciefer9062hurley@gmail.com"
            msg.set_content(body)
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender_email, password)
            smtp.send_message(msg)
            return var #returning the session valiable to store in session storage





#api for adding new Admins into the system
@app.route('/superadmin/insert', methods=['POST'])
def registeradmin():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    adetails = railwaydb["admin"] #pointing to admin collection
    sdetails = railwaydb["superadmin"] #pointing to superadmin collection
    valid = sdetails.find_one({"super_aid":request.json["sid"], "session":request.json["session"]}) #checking if superadmin session is still active
    if valid == None: #if not
        return "Initiating lockdown"
    else:
        umail = request.json["amail"]
        #validating the entered email address
        firstocc = 0
        firstdot = 0
        emailvalid = False
        saveatpoint = len(umail) + 1
        for i in range(len(umail)):
            if umail[i] == "@" and i!=0:
                if firstocc == 0:
                    saveatpoint = i
                firstocc = firstocc + 1
            if i > saveatpoint and umail[i] == ".":
                firstdot = firstdot + 1
        if firstocc == 1 and firstdot == 1  and umail[0] != "@" and umail[len(umail) - 1] != "." and umail[len(umail) - 1] != "@":
            emailvalid = True
        #checking the veracity 
        if request.json["aname"] == "":
            return "A name is needed for admin account creation."
        elif request.json["aid"] == "":
            return "Username needed for admin account creation."
        elif emailvalid == False:
            return "Enter valid email id."
        elif len(request.json["apass"]) < 8:
            return "Password must be of greater than 8 characters."
        else:
            inp = adetails.find_one({"aid":request.json["aid"]}) #flagging account with the username
            ine = adetails.find_one({"amail":request.json["amail"]}) #flagginf accounts with email address
            if inp == None and ine == None: #if not exists yet
                adminpass = request.json["apass"]
                adminpass = encryptpassword(adminpass) #encryting the password to store to database
                adetails.insert_one({"aname":request.json["aname"], "aid":request.json["aid"], "apass":adminpass, "amail":request.json["amail"], "lastlog":"", "session":""}) #inserting new admin information to database
                #sending an alert to database administrator
                subject = "Hello Super Admin!"
                body = "Admin - '" + request.json["aname"] + "' is added to the database."
                msg = EmailMessage()
                msg["Subject"] = subject
                msg["From"] = sender_email
                msg["To"] = "luciefer9062hurley@gmail.com"
                msg.set_content(body)
                with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                    smtp.login(sender_email, password)
                    smtp.send_message(msg)
                return "Admin Added Successfully" #returns this message
            else: #if exists
                return "Email is already associated with an Admin Account." #return this message





#api for changing Admin details into the system
@app.route('/superadmin/change', methods=['PUT'])
def adminchange():
    st = ""
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    adminCollection = railwaydb["admin"] #pointing to admin collection
    sdetails = railwaydb["superadmin"] #pointing to superadmin collection
    valid = sdetails.find_one({"super_aid":request.json["sid"], "session":request.json["session"]}) #checking if superadmin session is still active
    if valid == None: #if does not exist
        return "Initiating lockdown"
    else: 
        myadmin = adminCollection.find_one({"aid":request.json["aid"]}) #pointing to the admin account that needed a change
        if request.json["aid"] == "": #checking the veracity
            st = "username is needed to perform change"
        elif myadmin == None: #if the pointer points to no documents that means username doesnt exist.
            st = "Username doesn't exist or invalid"
        else: #if exist
            if request.json["aname"] != "": #checking if the field is left blank
                adminCollection.update_one({"aid":request.json["aid"]}, {"$set":{"aname":request.json["aname"]}}) #if not performing change
                st = "Admin Name updated successfully." #adding to msg
            if request.json["apass"] != "": #checking if the field is left blank
                adminCollection.update_one({"aid":request.json["aid"]}, {"$set":{"apass":encryptpassword(request.json["apass"])}}) #if not performing change
                st = st + " Password updated successfully." #adding to msg
            if request.json["newid"] != "": #checking if the field is left blank
                isadmin = adminCollection.find_one({"aid":request.json["newid"]}) #checking if the new username points to another admin just in case
                if isadmin == None: 
                    adminCollection.update_one({"aid":request.json["aid"]}, {"$set":{"aid":request.json["newid"]}}) #if not performing change
                    st = st + " Username updated successfully." #adding to msg
                else:
                    if request.json["aid"] == request.json["newid"]: #checking if the new id is same as before.
                        st = st + ""
                    else:
                        st = "Username already taken." #this else part is bound to come to this part, where the new username already points to another admin
        if st == "": #if no msg is concatenated
            st = "No changes made"
        else: #if any change is performed
            #send an alert
            subject = "Hello Super Admin!"
            body = "Details of Admin - '" + myadmin["aname"] + "' have been updated."
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = sender_email
            msg["To"] = "luciefer9062hurley@gmail.com"
            msg.set_content(body)
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                smtp.login(sender_email, password)
                smtp.send_message(msg)
        return st #returning the overall mesage to frontend 





#api for removing Admins out of the system
@app.route('/superadmin/delete', methods=['DELETE'])
def admindelete():
    st = ""
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    adminCollection = railwaydb["admin"] #pointing to admin collection
    sdetails = railwaydb["superadmin"] #pointing to superadmin collection
    valid = sdetails.find_one({"super_aid":request.json["sid"], "session":request.json["session"]}) #checking is superadmin session is still valid
    if valid == None: #if not
        return "Initiating lockdown"
    else:
        myadmin = adminCollection.find_one({"aid":request.json["aid"]}) #flagging the account to be deleted
        if request.json["aid"] == "": #checking the veracity
            st = "Username needed to remove an account"
        elif myadmin == None: #if no account if flagged that means no account exists supporting the input
            st = "Username is not found on database or invalid"
        else: #if flagged
            adminCollection.delete_one({"aid":request.json["aid"]}) #removing the account fron database
            #sending alert to database administrator
            subject = "Hello Super Admin!"
            body = "Admin - '" + myadmin["aname"] + "' is removed from the database."
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = sender_email
            msg["To"] = "luciefer9062hurley@gmail.com"
            msg.set_content(body)

            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                smtp.login(sender_email, password)
                smtp.send_message(msg)
            st = "Admin - " + str(myadmin["aname"]) + " removed Successfully"
        return st #returning the same msg to frontend






#api for fetching all active admins in system
@app.route('/superadmin/alladmin', methods=['GET']) #if accessed without session
def alladminerror():
    return blocked
@app.route('/superadmin/alladmin', methods=['POST']) #if accessed with session
def alladmin():
    st = ""
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    adetails = railwaydb["admin"] #pointing to admin collection
    sdetails = railwaydb["superadmin"] #pointing to superadmin collection
    valid = sdetails.find({"super_aid":request.json["sid"], "session":request.json["session"]}) #checking if the superadmin session is still valid 
    if valid == None: #if not
        return blocked
    else:
        alladmin = adetails.find({}) #getting all admin information
        for admin in alladmin: #iterating the documents and storing information
            if admin["session"] == "": #getting status information
                online = "Offline"
            else:
                online = "Online"
            if admin["aname"] != None: #capturing admins only with a valid name
                st = st + "<tr><td>" + str(admin["aname"]) + "</td><td>" + str(admin["aid"]) + "</td><td>" + online + "</td><td>" + str(admin["lastlog"]) + "</td></tr>" #embedding all data to table to push in frontend
        return '''<table border=1 class="table table-striped">
                    <thead>
                    <tr>
                        <th>Admin Name</th>
                        <th>Username</th>
                        <th>Status</th>
                        <th>Last logged in</th></tr></thead><tbody>''' + st + '''</tbody></table>''' #composing the table to return





#api for destroying superadmin session variable and loggin out
@app.route('/superadminlogout', methods=['POST'])
def superadminlogout():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    sdetails = railwaydb["superadmin"] #pointing to superadmin collection
    sdetails.update_one({"super_aid":request.json["sid"], "session":request.json["session"]}, {"$set":{"session":""}}) #session reset to mark superadmin as offline
    return "success" #trigger keyword to redirect to login page





#api for fetching super admin name for Welcome page
@app.route('/superadmininfo', methods=['POST'])
def superadmininfodb():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    adetails = railwaydb["superadmin"] #pointing to superadmin collection
    adminuser = adetails.find_one({"super_aid":request.json["sid"] , "session":request.json["session"]}) #checking if the superadmin session is still valid or not
    if adminuser == None: #if invalid
        return "Breached, Database Compromised!!!"
    else: #if not
        return "<p style='text-align:center;' class='mb-0'>Welcome " + str(adminuser["super_admin"]) + "!</p>" #returning the name of the user in the frontpage of superadmin





#~~~~~~~~~~~~~~~~~~~~~~~ADMIN-APIS~~~~~~~~~~~~~~~~~~~~~~~

#api for generating and sending OTP to admin after successfull pushing of credentials
@app.route('/adminotp', methods=['POST'])
def adminlockotp():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    adetails = railwaydb["admin"] #pointing to the admin collection of Railway database
    myotp = random.randint(100000,999999) #generating random 6 digit otp for auth
    myotp = str(myotp)
    smyotp = myotp
    myotp = encryptpassword(myotp) #encrypting otp for database store
    mypass = request.json["apass"]
    mypass = encryptpassword(mypass) #encrypting password for datbase match
    admin = adetails.find_one({"aid":request.json["aid"], "apass":mypass}) #checking if admin exists supporting this username and password
    if request.json["aid"] == "": #checking the veracity
        return "username is needed"
    elif request.json["apass"] == "": #checking the veracity
        return "password is needed"
    elif admin == None: #if admin doesn't exist by entered username and password
        return "invalid username or password"
    else: #if admin exists
        adetails.update_one({"aid":request.json["aid"], "apass":mypass}, {"$set":{"myotp":myotp}}) #setting the otp to the document
        myotp = smyotp
        sendotp(admin["amail"], myotp) #sending the copt of the otp to admin registered mail id
        return "OTP sent to registered email id and valid for only 3 minutes." #standard return





#api for checking if current session of admin is valid or not
@app.route('/returnpass', methods=['POST'])
def returnpass():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    adetails = railwaydb["admin"] #pointing admin collection of the Railway database
    ifuser = adetails.find_one({"aid":request.json["aid"], "session":request.json["session"]}) #checking if the session is still valid or not
    if ifuser != None: #if valid
        return "success" #trigger to login
    else: #if not
        return "no session" #trigger to force log out and login page





#api for checking the OTP of admin and successfully creating a session and saving info to DB
@app.route('/adminlock', methods=['POST'])
def adminlockdb():
    st = "incorrect credentials" #standard value 
    flagtime = datetime.now(timezone("Asia/Kolkata")) #flagging current timezone and date time
    flagtime = flagtime.strftime("%d/%m/%Y %H:%M:%S") #extracting only the useful information from the long time string
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    adetails = railwaydb["admin"] #poiting to the admin collection from Railway database
    adminpass = request.json["apass"]
    adminpass = encryptpassword(adminpass) #encrypting password for database match
    myotp = request.json["otp"]
    myotp = encryptpassword(myotp) #encrypting otp for database match
    inp = adetails.find_one({"aid":request.json["aid"], "apass": adminpass, "myotp":myotp}) #checking with the credentials if any admin exists or not
    if request.json["otp"] == "": #checking the veracity
        return "Please enter OTP"
    if inp == None: #if does not exist
        return "incorrect credentials"
    else: #if it does
        var = limlog(20) #generating random string of length 20 and using it as session variable
        adetails.update_one({"aid":request.json["aid"], "apass": adminpass}, {"$set":{"lastlog":str(flagtime), "myotp":"", "session":var}}) #setting the session variable and saving the flag time as last login
        #sending alert of login to Database Administrator
        subject = "Admin Alert"
        body = "Admin - '" + inp["aname"] + "' just logged in."
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = "luciefer9062hurley@gmail.com"
        msg.set_content(body)

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender_email, password)
            smtp.send_message(msg)
        return var #returning session variable to store in frontend session storage





#api for destroying admin session variable and loggin out
@app.route('/adminlogout', methods=['POST'])
def adminlogout():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    sdetails = railwaydb["admin"] #pointing the admin collection of Railway database
    sdetails.update_one({"aid":request.json["aid"], "session":request.json["session"]}, {"$set":{"session":""}}) #resetting the session of the current logged in admin
    return "success" #triggering force session clear and force redirect to login page





#api for fetching admin name for the Welcome page
@app.route('/admininfo', methods=['POST'])
def admininfodb():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    adetails = railwaydb["admin"] #pointing the admin collection of Railway database
    adminuser = adetails.find_one({"aid":request.json["aid"], "session":request.json["session"]}) #checking if the session is still valid or not
    if adminuser == None: #if not
        return "Please Login as an Admin." #triggers force login page redirect
    else:
        return "<p style='text-align:center;' class='mb-0'>Welcome " + str(adminuser["aname"]) + "!</p>" #returns html component of the username





#api for getting all the posted feedbacks to admin
@app.route('/admin/allfeed', methods=['GET']) #if accessed without any session 
def hehe():
    return blocked
@app.route('/admin/allfeed', methods=['POST']) #if accessed with session
def feedbackall():
    st = ""
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    adetails = railwaydb["admin"] #pointing the admin collection of Railway database
    valid = adetails.find_one({"aid":request.json["aid"], "session":request.json["session"]}) #checking the admin session if it is still valid
    if valid == None: #if not
        return blocked
    else: #else
        fdetails = railwaydb["feedbacks"] #pointing the feedbacks collection of Railway database
        allfeed = fdetails.find({}) #collecting every feedback in allfeed
        for feed in allfeed: #storing every feed by iteration and embedding into table like fashion
            st = st + "<tr><td><xmp>" + str(feed["cname"]) + "</xmp></td><td><xmp>" + str(feed["feedback"]) + "</xmp></td></tr>" #disabling any pre doc html code user might post and storing
        return '''<table border=1 class="table table-striped">
                    <thead>
                    <tr>
                        <th>Peoples</th>
                        <th>Feedbacks</th></tr></thead><tbody>''' + st + '''</tbody></table>''' #preparing a table content to push in frontend





#api for adding a new train to DB
@app.route('/admin/train/insert', methods=['POST'])
def t_insert():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    db = mongodb_client["Railway"] #pointing to the Railway database for operation
    trainCollection = db["Trains"] #pointing the Trains collection of Railway database
    coachCollection = db["Coaches"] #pointing the Coaches collection of Railway database
    adminCollection = db["admin"] #pointing the admin collection of Railway database
    myadmin = adminCollection.find_one({"aid": request.json["aid"], "session":request.json["session"]}) #checking admin session if it is still available
    if myadmin == None: #if invalid
        return "Please Login as an Admin." #triggers forced redirection to login page along with session clear
    else:
        trains = trainCollection.find({}) #getting all trail documents
        coaches = coachCollection.find({}) #getting all coach documents
        atime = request.json["dtime"] + 1 #assuming departure time is 1 hour prior of arrival by default
        lastcoachsn = 0 #flag to get last coach document and it's serial number- sn
        lasttrainsn = 0 #flag to get last train document and it's serial number - otsn
        noft = trainCollection.count_documents({}) #getting number of train documents
        nofc = coachCollection.count_documents({}) #getting number of coach documents
        isavailable = trainCollection.find_one({"istation":request.json["istation"] , "dtime":request.json["dtime"]}) #checking if any train is already available by this time slot at this station
        if request.json["trainname"] == "": #checking the veracity
            return "Train Name can not be empty."
        elif request.json["istation"] == "From Station" or request.json["dstation"] == "To Station": #checking the veracity
            return "Initial station and Destination station must be selected."
        elif request.json["istation"] == request.json["dstation"]: #checking the veracity
            return "Initial Station and Destination Station can not be same."
        elif request.json["dtime"] == 0.5: #checking the veracity
            return "Departure time must be selected."
        elif isavailable != None: #if exists
            return "A train is already assigned to this time frame to station - " + str(request.json["istation"]) +"."
        else: #if not
            if trains == None: #for the condition where there is no document already. this is the first document to be added 
                trainCollection.insert_one({"otsn":1, "trainname":request.json["trainname"], "istation":request.json["istation"], "dstation":request.json["dstation"], "dtime":request.json["dtime"], "atime": atime, "noc":1}) #insertion of a train document
                coachCollection.insert_one({"sn":1, "noas": 10, "type":"NAC", "nobs": 0, "otsn":1}) #insertion of a coach document
            else: #for the condition where there exists atleast one document and we are about to add more.
                #code to get the last train document serial number
                ptr = 1
                for doc in trains:
                    if(noft == ptr):
                        lasttrainsn = doc["otsn"]
                    ptr = ptr + 1
                trainCollection.insert_one({"otsn":lasttrainsn+1, "trainname":request.json["trainname"], "istation":request.json["istation"], "dstation":request.json["dstation"], "dtime":request.json["dtime"], "atime": atime, "noc":1}) #insertion of a train document
                #code to get the last coach document serial number
                pco = 1
                for doc in coaches:
                    if(nofc == pco):
                        lastcoachsn = doc["sn"]
                    pco = pco + 1
                coachCollection.insert_one({"sn":lastcoachsn+1, "noas": 40, "type":"NAC", "nobs": 0, "otsn":lasttrainsn+1}) #insertion of a coach document
                #sending alert to Superadmin of the recent change
                subject = "Hello Super Admin!"
                body = "Admin - '" + myadmin["aname"] + "' added a new train to the database.\n\nThe Details of the new train :\nTrain Name - " + request.json["trainname"] + "\nFrom Station - " + request.json["istation"] + "\nTo Station - " + request.json["dstation"] + "\nDeparture time - " + str(request.json["dtime"]) + "\n"
                msg = EmailMessage()
                msg["Subject"] = subject
                msg["From"] = sender_email
                msg["To"] = "luciefer9062hurley@gmail.com"
                msg.set_content(body)
                with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                    smtp.login(sender_email, password)
                    smtp.send_message(msg)
            captureCoach = coachCollection.find_one({"sn":lastcoachsn+1}) #getting the information of the recently added coach
            return "Train added successfully with serial no " + str(lasttrainsn+1) + ". " + "Coach added aditionally with serial no " + str(lastcoachsn+1) + ". And it is an " + str(captureCoach["type"]) + " coach." #returning the message to frontend





#api for manipulating existing train value
@app.route('/admin/train/edit', methods=['PUT'])
def t_edit():
    st = ""
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    trainCollection = railwaydb["Trains"] #pointing the Trains collection of Railway database
    adminCollection = railwaydb["admin"] #pointing the admin collection of Railway database
    admin = adminCollection.find_one({"aid":request.json["aid"], "session":request.json["session"]}) #checking if the admin session is still valid
    mytrain = trainCollection.find_one({"otsn":request.json["tno"]}) #getting the train document to perform edit
    if admin == None: #if session not valid
        return "Please Login as an Admin." #triigerring to force redirect to login page clearing the session
    else: #if valid
        if request.json["tno"] == None: #checking the veracity
            st = "Train Number needed to perform this task."
        elif mytrain == None: #checking if any train exists by the train number
            st = "No train found against the train."
        else: #if found
            #checking if new train name field is empty or not
            if request.json["tname"] != "": #if not
                trainCollection.update_one({"otsn":request.json["tno"]}, {"$set":{"trainname":request.json["tname"]}}) #setting the new updated value
                st = "Train Name updated successfully." #message concatenation
            #checking if departure time field is empty or not
            if request.json["dtime"] != 0.5: #if not
                alt = trainCollection.find_one({"otsn":request.json["tno"], "dtime":request.json["dtime"]}) #checking if the new entered time is suitable or not
                if alt != None: #if not
                    st = st + " A train already exists at this time on this station." #message concatenation
                else: 
                    trainCollection.update_one({"otsn":request.json["tno"]}, {"$set":{"dtime":request.json["dtime"]}}) #setting the new updated value
                    st = st + " Train Time updated successfully." #message concatenation
        if st == "": #if no changed made so far
            st = "No changes made"
        else: #if changes made
            #sending a superadmin alert
            subject = "Hello Super Admin!"
            body = "Admin - '" + admin["aname"] + "' updated a train.\n\nThe updated details of the train no - " + str(request.json["tno"]) + ":\nTrain Name - " + request.json["tname"] + "\nDeparture time - " + str(request.json["dtime"]) + "\n"
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = sender_email
            msg["To"] = "luciefer9062hurley@gmail.com"
            msg.set_content(body)
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                smtp.login(sender_email, password)
                smtp.send_message(msg)
        return st #return the message to frontend





#api for removing a train from the system
@app.route('/admin/train/delete', methods=['DELETE'])
def t_delete():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    trainCollection = railwaydb["Trains"] #pointing the Trains collection of Railway database
    coachCollection = railwaydb["Coaches"] #pointing the Coaches collection of Railway database
    ticketCollection = railwaydb["Tickets"] #pointing the Tickets collection of Railway database
    userCollection = railwaydb["users"] #pointing the user collection of Railway database
    adminCollection = railwaydb["admin"] #pointing the admin collection of Railway database
    admin = adminCollection.find_one({"aid":request.json["aid"], "session": request.json["session"]}) #checking if the admin session is still valid
    isnameavailable = trainCollection.find_one({"otsn":request.json["trainno"]}) #flagging the train document
    if admin == None: #if session not valid
        return "Please Login as an Admin." #triggers force redirection to login page clearing sesion storage
    else: #if session is valid
        if request.json["trainno"] == None: #checking the veracity
            return "Please enter train number to remove a train"
        elif request.json["trainno"] < 0: #checking the veracity
            return "Train number can not be zero ro negative"
        elif isnameavailable == None: #if there is no train flagged
            return "Train not found."
        else: #if flagged
            queryarg1={"otsn":request.json["trainno"]} #setting a general query
            ptr = trainCollection.find_one(queryarg1) #flagging the train
            trainCollection.delete_one(queryarg1) #deleting the train by that same general query
            coachCollection.delete_many({"otsn":ptr["otsn"]}) #using this flag to delete coaches where train number matches to query
            tickets = ticketCollection.find({"otsn":request.json["trainno"]}) #flagging all tickets associated with the train
            for ticket in tickets: #deletion by iteration
                user = userCollection.find_one({"ph_num":str(ticket["ph_num"])}) #flagging every user of the tickers
                #sending individual mails to them to that their ticket is no longer valid as the train has been removed from the database
                subject = "Your ticket has been cancelled"
                body = "Hello " + str(ticket["cus_name"]) + "! Your reservation on from " + str(ticket["istation"]) + " to " + str(ticket["dstation"]) + " train has been cancelled due to system change. Sorry for the inconvenience."
                msg = EmailMessage()
                msg["Subject"] = subject
                msg["From"] = sender_email
                msg["To"] = user["umail"]
                msg.set_content(body)
                with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                    smtp.login(sender_email, password)
                    smtp.send_message(msg)
            ticketCollection.update_many({"otsn":request.json["trainno"]}, {"$set": {"remarks":"Cancelled due to system change", "isvalid":False}}) #finally making all those tickets invalid and updating the database
            #sending a superadmin alert about the changed made
            subject = "Hello Super Admin!"
            body = "Admin - '" + admin["aname"] + "' deleted train no - " + str(request.json["trainno"]) + "."
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = sender_email
            msg["To"] = "luciefer9062hurley@gmail.com"
            msg.set_content(body)
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                smtp.login(sender_email, password)
                smtp.send_message(msg)
            return "Train No - " + str(ptr["otsn"]) + ", '" + str(ptr["trainname"]) + "' arriving at " + str(ptr["dtime"]) + " O'clock removed successfully" #returning the message to frontend





#api for adding a coach to a train
@app.route('/admin/coach/insert', methods=['POST'])
def c_insert():
    message = ""
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    coachCollection = railwaydb["Coaches"] #pointing the Coached collection of Railway database
    trainCollection = railwaydb["Trains"] #pointing the Trains collection of Railway database
    adminCollection = railwaydb["admin"] #pointing the admin collection of Railway database
    admin = adminCollection.find_one({"aid":request.json["aid"], "session":request.json["session"]}) #checking if the admin session is still valid or not 
    if admin == None: #if not
        return "Please Login as an Admin." #triggers force redirection to login page after session storage clear
    else: #if valid
        nofc = coachCollection.count_documents({}) #getting number of coaches
        coachnos = coachCollection.find({}) #gethering all coach documents
        lasttrainno = trainCollection.find_one({"otsn":request.json["trainno"]}) #flagging the train where the coach is to be added
        if request.json["trainno"] == None: #checking the veracity
            message = "Trainno can not be empty."
        elif request.json["trainno"] <= 0: #checking the veracity
            message = "Trainno can not be negative."
        elif lasttrainno == None: #if no train is flagged
            message = "There is no such train."
        elif request.json["nos"] == None: #checking the veracity
            message = "Number of seats can not be empty."
        elif request.json["nos"] <= 0: #checking the veracity
            message = "Number of seats can not be less that zero."
        elif request.json["nos"] > 100: #checking the veracity
            message = "Number of seats can not be greater than 100."
        elif request.json["coachtype"] == "Coach Type": #checking the veracity
            message = "Coach type must be selected."
        else:
            #getting the last coach serial number
            ptr = 1
            for doc in coachnos:
                if(nofc == ptr):
                    lastcoachno = doc["sn"]
                ptr = ptr + 1
            queryarg1={"sn":lastcoachno+1, "noas":request.json["nos"], "type":request.json["coachtype"], "nobs":0, "otsn":request.json["trainno"]} #preparing general query
            queryarg2 = {"otsn":request.json["trainno"]} #preparing general query
            coachCollection.insert_one(queryarg1) #adding the new coach document to database
            nocpart = coachCollection.count_documents(queryarg2) #now updated number of document associated with the train
            trainCollection.update_one(queryarg2, {'$set': {'noc': nocpart}}) #updating the number of coached section of train collection
            #sending an alert to superadmin of the recent changes
            subject = "Hello Super Admin!"
            body = "Admin - '" + admin["aname"] + "' added a new coach to train no - " + str(request.json["trainno"]) + ".\nThe new coach details - \nCoach No - " + str(lastcoachno+1) + "\nType - " + request.json["coachtype"] + "\nNumber of available seats - " + str(request.json["nos"])
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = sender_email
            msg["To"] = "luciefer9062hurley@gmail.com"
            msg.set_content(body)
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                smtp.login(sender_email, password)
                smtp.send_message(msg)
            message = "Coach No " + str(lastcoachno+1)+ " of type " + str(request.json["coachtype"])+ " is added successfully with " + str(request.json["nos"]) + " Seat(s) to Train No " + str(request.json["trainno"]) + "." #comsposing the frontend message
        return message #returning the composed text





#api for removing a coach from FB
@app.route('/admin/coach/delete', methods=['DELETE'])
def c_delete():
    msge = ""
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    coachCollection = railwaydb["Coaches"] #pointing the Coaches collection of Railway database
    trainCollection = railwaydb["Trains"] #pointing the Trains collection of Railway database
    ticketCollection = railwaydb["Tickets"] #pointing the Tickets collection of Railway database
    adminCollection = railwaydb["admin"] #pointing the admin collection of Railway database
    admin = adminCollection.find_one({"aid":request.json["aid"], "session":request.json["session"]}) #checking if the admin session is still valid or not
    if admin == None: #if not
        return "Please Login as an Admin." #triggers force redirection to the login page aftr clearing the sesion storage
    else: #if valid
        userCollection = railwaydb["users"] #pointing user collection of Railway database
        isavailable = coachCollection.find_one({"sn":request.json["coachno"]}) #getting the coach document by its serial number
        if request.json["coachno"] == None: #checking the veracity
            msge = "Coach No is needed to delete a coach"
        elif request.json["coachno"] < 1: #checking the veracity
            msge = "Coach No can not be zero ro negative"
        elif isavailable == None: #if there is no document by the serial number
            msge= "No such coach to be deleted"
        else: #if there exists
            otsn = isavailable["otsn"] #getting the serial number of the train which is associated with the coach
            coachCollection.delete_one({"sn":request.json["coachno"]}) #deleteing the selected coach document
            trainCollection.update_one({"otsn":otsn}, {"$inc": {"noc": -1}}) #updating the train document number of coaches field
            tickets = ticketCollection.find({"coachno":request.json["coachno"]}) #flagging all the tickets associated with the coach
            for ticket in tickets: #interating every ticket and performing the following
                user = userCollection.find_one({"ph_num":str(ticket["ph_num"])}) #flagging the user who booked the ticket
                #sending the cancellation message on email
                subject = "Your ticket has been cancelled"
                body = "Hello " + str(ticket["cus_name"]) + "! Your reservation on from " + str(ticket["istation"]) + " to " + str(ticket["dstation"]) + " train has been cancelled due to system change. Sorry for the inconvenience."
                msg = EmailMessage()
                msg["Subject"] = subject
                msg["From"] = sender_email
                msg["To"] = user["umail"]
                msg.set_content(body)
                with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                    smtp.login(sender_email, password)
                    smtp.send_message(msg)
            ticketCollection.update_many({"coachno":request.json["coachno"]}, {"$set": {"remarks":"Cancelled due to system change", "isvalid":False}}) #updating all tickets to be false and setting remarks as it was cancelled due to system change
            #sending an admin alert of the aforementioned change
            subject = "Hello Super Admin!"
            body = "Admin - '" + admin["aname"] + "' deleted a coach of serial number - " + str(request.json["coachno"])
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = sender_email
            msg["To"] = "luciefer9062hurley@gmail.com"
            msg.set_content(body)
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                smtp.login(sender_email, password)
                smtp.send_message(msg)
            msge = "Coach deleted successfully."
        return msge #returning message to frontend





#api for changing coach information like type and number of seats
@app.route('/admin/coach/change', methods=['PUT'])
def ctypechange():
    st = ""
    mongodb_client=pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    db=mongodb_client["Railway"] #pointing to the Railway database for operation
    coachCollection = db["Coaches"] #pointing the Coaches collection of Railway database
    adminCollection = db["admin"] #pointing the admin collection of Railway database
    admin = adminCollection.find_one({"aid":request.json["aid"], "session":request.json["session"]}) #checking if the admin session is still valid or not
    if admin == None: #if not
        return "Please Login as an Admin." #triggers force redirection to the login page aftr clearing the sesion storage
    else: #if valid
        coachtobechanged = coachCollection.find_one({"sn":request.json["coachno"]}) #flagging the coach document
        if request.json["coachno"] == None: #checking the veracity
            return "Coach no needed to make a change."
        elif request.json["coachno"] < 1: #checking the veracity
            return "Coach no can not be zero or negative."
        elif coachtobechanged == None: #if flagged content is none
            return "No such coach exists."
        else: #if there exists a flagged document
            if request.json["type"] != "Coach Type": #checking if type field is empty or not
                oldtype = coachtobechanged["type"] #saving the old type of the coach
                coachCollection.update_one({"sn":coachtobechanged["sn"]}, {"$set": {"type": request.json["type"]}}) #updating to new data on type field
                st = st + "Coach Type changed from " + str(oldtype) + " to " + str(request.json["type"]) + ". " #concatenating text
            if request.json["noas"] != None: #checking if nmber of avaiable seats-field is empty or not
                if request.json["noas"] < 1: #checking the veracity
                    st = st + "Number of Seats can not be zero or negative."
                else:
                    oldnoas = coachtobechanged["noas"] #saving the old number of available seats
                    coachCollection.update_one({"sn":coachtobechanged["sn"]}, {"$set": {"noas": request.json["noas"]}}) #updating to new data on the field
                    st = st + "Coach available seats changed from " + str(oldnoas) + " to " + str(request.json["noas"]) + "." #concatenating text
            if request.json["type"] == "Coach Type" and request.json["noas"] == None: #if the both field is empty
                st = "No changes made."
            else: #if not
                #sending alert to superadmin for recent changes
                subject = "Hello Super Admin"
                body = "Admin - " + admin["aname"] + " updated coach with serial number - " + str(request.json["coachno"]) + " \nThe Updated coach details - \nCoach Type - " + str(request.json["type"])+ "\nNumber of available seats - " + str(request.json["noas"])
                msg = EmailMessage()
                msg["Subject"] = subject
                msg["From"] = sender_email
                msg["To"] = "luciefer9062hurley@gmail.com"
                msg.set_content(body)
                with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                    smtp.login(sender_email, password)
                    smtp.send_message(msg)
            return st #returning the final composed text to frontend





#api for admin ticket cancel
@app.route('/admin/cancelticket', methods=['PUT'])
def cticket():
    st = ""
    mongodb_client=pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    db=mongodb_client["Railway"] #pointing to the Railway database for operation
    ticketCollection = db["Tickets"] #pointing the Tickets collection of Railway database
    coachCollection = db["Coaches"] #pointing the Coaches collection of Railway database
    userCollection = db["users"] #pointing the users collection of Railway database
    quesrytorun = {"_id":ObjectId(request.json["ticketno"])} #saving generalized query to run later
    ticket = ticketCollection.find_one(quesrytorun) #getting the ticket by the information
    adminCollection = db["admin"] #pointing the admin collection of Railway database
    admin = adminCollection.find_one({"aid":request.json["aid"], "session":request.json["session"]}) #checking if admin session is still available 
    if admin == None: #if not
        st = "You have to login as an Admin." #triggers force redirection to the login page aftr clearing the sesion storage
    elif ticket == None: #checking if ticket number matches any details
        st = "Entered details doesn't match any record."
    elif ticket["isvalid"] == False: #checking if the ticket is already cancelled previously
        st = "Ticket is already " + str(ticket["remarks"])
    else: #if session valid, ticket exists and not cancelled previosly
        user = userCollection.find_one({"ph_num":str(ticket["ph_num"])}) #flagging the user who booked ticket
        ticketCollection.update_one(quesrytorun, {"$set":{"remarks":"Cancelled By Admin.", "isvalid":False}}) #updating the ticket on query to be invalid
        coachCollection.update_one({"sn":ticket["coachno"]}, {"$inc":{"noas": +ticket["nos"], "nobs": -ticket["nos"]}}) #updating coach seat information
        #sending cancellation message to user
        subject = "Your ticket has been cancelled"
        body = "Hello " + str(ticket["cus_name"]) + "! Your reservation on from " + str(ticket["istation"]) + " to " + str(ticket["dstation"]) + " train has been cancelled by Admin."
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = user["umail"]
        msg.set_content(body)
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender_email, password)
            smtp.send_message(msg)
        st = "Hello Admin! Ticket booked for " + str(ticket["cus_name"]) + " has been cancelled successfully." #composing the message
    return st #returning the message to frontend





#api for fetching all tickets booked
@app.route('/admin/alltickets', methods=['POST'])
def alltickets():
    st = ""
    mongodb_client=pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    db=mongodb_client["Railway"] #pointing to the Railway database for operation
    trainCollection = db["Trains"] #pointing the Trains collection of Railway database
    ticketCollection = db["Tickets"] #pointing the Tickets collection of Railway database
    adminCollection = db["admin"] #pointing the admin collection of Railway database
    admin = adminCollection.find_one({"aid":request.json["aid"], "session":request.json["session"]}) #checking if the admin session is stil lactive or not
    if admin == None: #if not
        st = "You have to login as an Admin." #triggers force redirection to the login page aftr clearing the sesion storage
    else: #if valid
        tickets = ticketCollection.find({}) #getting every ticket document from database
        for ticket in tickets: #iterating every ticket
            if ticket["isvalid"] == False: #for every ticket isvalid convention to write in table
                isvalid = "Invalid"
            else:
                isvalid = "Valid"

            train = trainCollection.find_one({"otsn": ticket["otsn"]}) #checking if train if available supporting the ticket
            if train!=None: #if not then only
                st = st + "<tr><td>" + str(train["trainname"]) + "</td><td>" + str(ticket["_id"]) + "</td><td>" + str(ticket["cus_name"]) + "</td><td>" + str(ticket["coachno"]) + "</td><td>" + str(ticket["type"]) + "</td><td>" + str(ticket["nos"]) + "</td><td>" + str(ticket["ph_num"]) + "</td><td>" + isvalid + "</td><td>" + str(ticket["remarks"]) + "</td></tr>" #composing the mass of table inside
        st = '''<table class="table table-striped">
                    <thead>
                    <tr>
                        <th>Train Name</th>
                        <th>Ticket No</th>
                        <th>Customer Name</th>
                        <th>Coach No</th>
                        <th>Coach Type</th>
                        <th>Number of seats</th>
                        <th>Phone Number</th>
                        <th>Status</th>
                        <th>Remarks</th>
                    </tr></thead></tbody>''' + st + '''</tbody></table>''' #embedding into the table in HTML format to push in frontend
    return st #returning the push message





#api for fetching all in one table for Admin
@app.route('/admin/mothertable', methods=['GET']) #wheather accessed without session information
def mothertableerror():
    return blocked
@app.route('/admin/mothertable', methods=['POST']) #wheather accessed with session information
def mothertable():
    st = ""
    mongodb_client=pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    db=mongodb_client["Railway"] #pointing to the Railway database for operation
    adetails = db["admin"] #pointing the admin collection of Railway database
    valid = adetails.find_one({"aid":request.json["aid"], "session":request.json["session"]}) #checking if session is still active
    if valid == None: #if not pass blocked data
        return blocked #triggers force redirection to the login page after session storage clear
    else:
        trainCollection = db["Trains"] #pointing the Trains collection of Railway database
        coachCollection = db["Coaches"] #pointing the Coaches collection of Railway database
        start = 1 #counter to get serialized table row
        coaches = coachCollection.find({}) #getting all the coach information
        for coach in coaches: #interating every coach and for every coach
            flagtrain = trainCollection.find_one({"otsn":coach["otsn"]}) #getting the train document associated with the coach
            #converting db time to readable time
            if type(flagtrain["dtime"]) == float:
                dep_time = str(int(flagtrain["dtime"] - 0.5)) + ".30" 
            else:
                dep_time = str(flagtrain["dtime"]) + ".00"
            #composing the large row with every information available except for the users and tickets
            st = st + "<tr><td>" + str(start) + "</td><td>" + str(coach["sn"]) + "</td><td>" + coach["type"] +  "</td><td>" + str(flagtrain["otsn"]) + "</td><td>" + flagtrain["trainname"] + "</td><td>" + flagtrain["istation"] + "</td><td>" + dep_time + "</td><td>" + flagtrain["dstation"] + "</td><td>" + str(float(dep_time) + 1) + str(0) + "</td><td>" + str(flagtrain["noc"]) + "</td><td>" + str(coach["noas"]) + "</td><td>" + str(coach["nobs"]) + "</td></tr>"
            start = start + 1
        st = '''<table class="table table-striped">
                    <thead>
                    <tr>
                        <th>Serial No</th>
                        <th>Coach No</th>
                        <th>Coach Type</th>
                        <th>Train No</th>
                        <th>Train Name</th>
                        <th>Initial Station</th>
                        <th>Departure Time</th>
                        <th>Destination Station</th>
                        <th>Arrival Time</th>
                        <th>Coaches on Train</th>
                        <th>Available Seats</th>
                        <th>Booked Seats</th>
                    </tr></thead><tbody>''' + st +'''</tbody>
                </table>''' #embedding the table body to table in HTML format
        return st #pushing the table content to frontend





#~~~~~~~~~~~~~~~~~~~~~~~USER-APIS~~~~~~~~~~~~~~~~~~~~~~~

#api for sending a reset password otp
@app.route('/forgototp', methods=['POST'])
def forgototp():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    userCollection = railwaydb["users"] #pointing to the users collection of Railway database
    user = userCollection.find_one({"umail":request.json["umail"]}) #flagging the user that has the email.
    if user == None: #if flagged document is null
        return "Email is invalid or not yet associated with an account."
    else: #if npt
        myotp = random.randint(100000,999999) #generate a new otp
        myotp = str(myotp)
        sendotp(user["umail"], myotp) #sending the copy of otp to user
        myotp = encryptpassword(myotp) #encrypting otp for database
        userCollection.update_one({"umail":user["umail"]}, {"$set" : {"myotp":myotp}}) #updating myotp section with the new otp
        return "OTP sent and only valid for 3 minutes." #returning the msg





#api for checking if entered OTP is the same as Database OTP
@app.route('/checkotp', methods=['POST'])
def checkotp():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    userCollection = railwaydb["users"] #pointing to the users collection of Railway database
    user = userCollection.find_one({"umail":request.json["umail"]}) #flagging the user that has the email.
    if user == None: #if flagged document is null
        return "Value changed, Can't perform." #triggers veracity lockdown if user tries to change values mid way
    else:
        userotp = userCollection.find_one({"umail":request.json["umail"], "myotp":encryptpassword(request.json["myotp"])}) #checking if by the otp any document gets returned
        if userotp == None: #if it doesn't return 
            return "Wrong OTP"
        else: #if it does
            return "OTP matched"





#api for changing password but only with a valid request
@app.route('/changepass', methods=['GET']) #port to access changepass api without valid data
def lmaonuub():
    return blocked #triggers force system ui shutdown, however backend stays alive
@app.route('/changepass', methods=['POST']) #user with valid data
def changepass():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    userCollection = railwaydb["users"] #pointing to users collection of Railway database
    user = userCollection.find_one({"umail":request.json["umail"]}) #flagging the account that needs password change
    if user == None: #if flag returns no account
        return "Value changed, Can't perform." #triggers the system logout clearing session data
    elif request.json["pass1"] != request.json["pass2"]: #checking the veracity
        return "passwords doesn't match"
    else: #if flag does return account
        userCollection.update_one({"umail":request.json["umail"]}, {"$set" : {"upass":encryptpassword(request.json["pass2"]), "myotp":""}}) #updated the password section, and resets the otp section
        return "password changed." #triggers the system to redirect on login page clearing any faulty session data





#api for resetting 'forgot api' OTP
@app.route('/resetotpuser', methods=['POST'])
def resetotpuser():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    details = railwaydb["users"] #pointing to users collection of Railway database
    details.update_one({"umail":request.json["umail"]}, {"$set":{"myotp":""}}) #resetting the otp
    return "OTP expired, Acquire a new one." #standard system display





#api for checking id current session of user is valid or not
@app.route('/returnpassuser', methods=['POST'])
def returnpassuser():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    udetails = railwaydb["users"] #pointing to users collection of Railway database
    valid = udetails.find_one({"ph_num":request.json["ph_num"], "session":request.json["session"]}) #checking if user session is still valid or not
    if valid == None: #if not
        return "no session"  #triggers the system to redirect on login page clearing any faulty session data
    else: #if valid
        return "success" #triggers the system to login without any credentials





#api for checking the OTP of user and successfully creating a session and saving info to DB
@app.route('/userlock', methods=['POST'])
def userlockdb():
    flagtime = datetime.now(timezone("Asia/Kolkata")) #flagging the current date and time data
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    udetails = railwaydb["users"] #pointing to users collection of Railway database
    userpass = request.json["upass"] 
    userpass = encryptpassword(userpass) #encrypting user password for database match
    inp = udetails.find_one({"ph_num":request.json["ph_num"], "upass": userpass}) #flagging user document supporting the given credentials
    if inp == None: #if flag returns no document
        return "invalid username or password"
    else: #if it does
        var = limlog(20) #generating a random string of 20 length for session variable
        udetails.update_one({"ph_num":request.json["ph_num"]}, {"$set":{"lastlog":str(flagtime), "session":var}}) #setting the session to database
        return var #returning the session for frontend usage or to store in session storage





#api for user registration
@app.route('/registeruser', methods=['POST'])
def registeruser():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    udetails = railwaydb["users"] #pointing to users collection of Railway database
    umail = request.json["umail"] 
    firstocc = 0
    firstdot = 0
    #checking if email is valid or not
    emailvalid = False
    saveatpoint = len(umail) + 1
    for i in range(len(umail)):
        if umail[i] == "@" and i!=0:
            if firstocc == 0:
                saveatpoint = i
            firstocc = firstocc + 1
        if i > saveatpoint and umail[i] == ".":
            firstdot = firstdot + 1

    if firstocc == 1 and firstdot == 1  and umail[0] != "@" and umail[len(umail) - 1] != "." and umail[len(umail) - 1] != "@": #if valid
        emailvalid = True
    if int(request.json["ph_num"])>9999999999 or int(request.json["ph_num"])<6000000000: #checking the veracity
        return "Please enter a valid phone number."
    elif emailvalid == False: #checking the veracity
        return "Please enter a correct email." 
    elif len(request.json["upass"]) < 8: #checking the veracity
        return "Password must be of greater than 8 characters."
    else:
        inp = udetails.find_one({"ph_num":request.json["ph_num"]}) #getting the account eith given phone number
        ine = udetails.find_one({"umail" : request.json["umail"]}) #getting the account with given email 
        if inp == None and ine == None: #checking if both flags are non existant
            #if it is
            userpass = request.json["upass"] 
            userpass = encryptpassword(userpass) #encrypting userpass for database check 
            udetails.insert_one({"uname":request.json["uname"], "ph_num":request.json["ph_num"], "upass":userpass, "umail" : request.json["umail"], "lastlog":""}) #inserting user as a new document
            #sending a welcome message to the new user
            subject = "Welcome " + request.json["uname"] + "!"
            body = "You've been successfully registered. Thank you."
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = sender_email
            msg["To"] = request.json["umail"]
            msg.set_content(body)
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                smtp.login(sender_email, password)
                smtp.send_message(msg)
            return "Registered Successfully" #system text
        else:
            #if it is not
            return "Phone Number or email is already associated with an account."





#api for destroying user session variable and loggin out
@app.route('/userlogout', methods=['POST'])
def userlogout():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    udetails = railwaydb["users"] #pointing to users collection of Railway database
    udetails.update_one({"ph_num":request.json["ph_num"], "session":request.json["session"]}, {"$set":{"session":""}}) #after requesting logout resetting the session .
    return "success" #triggers force redirection of login page after session storage clear





#api for fetching user name for the Welcome page
@app.route('/userinfo', methods=['POST'])
def userinfodb():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    udetails = railwaydb["users"] #pointing to users collection of Railway database
    user = udetails.find_one({"ph_num":request.json["ph_num"], "session":request.json["session"]}) #flagging the user with given session details
    if user == None: #if flag returns no document
        return "<p style='text-align:center;' class='mb-0'>Welcome User!</p><footer style='text-align:center;' class='lead'><small class='text-muted'>You must log in to use certain features.</small></footer>"
    else: #if it does return document
        return "<p style='text-align:center;' class='mb-0'>Welcome " + str(user["uname"]) + "!</p>"





#api for searching train by stations
@app.route('/train/view', methods=['POST'])
def t_view():
    st = ""
    mongodb_client=pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    db=mongodb_client["Railway"] #pointing to the Railway database for operation
    trainCollection = db["Trains"] #pointing to Trains collection of Railway database
    if request.json["istation"] == "From Station" or request.json["dstation"] == "To Station": #checking the veracity
        st = "<h4 class='display-6' style='text-align:center;'>Input needed to complete the search.</h4>"
    elif request.json["istation"] == request.json["dstation"]: #checking the veracity
        st = "<h4 class='display-6' style='text-align:center;'>Source and Destination can not be same.</h4>"
    else: #if data integrity validates
        alltrains = trainCollection.find({"istation":request.json["istation"], "dstation":request.json["dstation"]}) #getting the trains that run between the teo station
        if alltrains == None: #if not found any
            st = "<h4 class='display-6' style='text-align:center;'>No train found on the route.</h4>"
        else: #if found atleast one
            for train in alltrains: #iterating every train and performing those operation below
                #converting all database times to readable ones
                if type(train["dtime"]) == float:
                    dtime = str(int(train["dtime"])) + ".30"
                else:
                    dtime = str(train["dtime"]) + ".00"
                if type(train["atime"]) == float:
                    atime = str(int(train["atime"])) + ".30"
                else:
                    atime = str(train["atime"]) + ".00"
                #concatenating every row with valid datasets
                st = st + "<tr><td>" + str(train["otsn"]) + "</td><td>" + train["trainname"] + "</td><td>" + train["istation"] + "</td><td>" + train["dstation"] + "</td><td>" + dtime + "</td><td>" + atime + "</td><td>" + str(train["noc"]) + "</td></tr>" #table body to be pushed
            st = '''<table class="table">
                    <thead class="thead-light">
                        <tr>
                        <th scope="col">Train Number</th>
                        <th scope="col">Train Name</th>
                        <th scope="col">Initial Station</th>
                        <th scope="col">Destination Station</th>
                        <th scope="col">Departure time</th>
                        <th scope="col">Arrival Time</th>
                        <th scope="col">Number of Coaches</th>
                        </tr>
                        </thead><tbody>''' + st + '''</tbody></table>''' #embedding the table body into HTML format
    return st #returning the table to be pushed in the frontend





#api for getting coach information by stations
@app.route('/coach/view', methods=['POST'])
def c_view():
    st = ""
    mongodb_client=pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    db=mongodb_client["Railway"] #pointing to the Railway database for operation
    coachCollection = db['Coaches'] #pointing to Coaches collection of Railway database
    trainCollection = db["Trains"] #pointing to Trains collection of Railway database
    if request.json["istation"] == "From Station" or request.json["dstation"] == "To Station" or request.json["type"] == "Coach type": #checking the veracity
        st = "<h4 class='display-6'>Input needed to perform search.</h4>"
    elif request.json["istation"] == request.json["dstation"]: #checking the veracity
        st = "<h4 class='display-6'>Source and destination can not be same.</h4>"
    else: #if data is truthful
        trains = trainCollection.find({"istation":request.json["istation"], "dstation":request.json["dstation"]}) #flagging every train running between those two station
        for train in trains: #for every train
            coaches = coachCollection.find({"otsn":train["otsn"], "type":request.json["type"]}) #flag all the coaches associated with that immediate train
            for coach in coaches: #for every coaches
                st = st + "<tr><td>" + str(coach["sn"]) + "</td><td>" + str(train["otsn"]) + "</td><td>" + train["trainname"] + "</td><td>" + coach["type"] + "</td><td>" + str(coach["noas"]) + "</td><td>" + str(coach["nobs"]) + "</td></tr>" #composing the body using the required datasets
        st = '''<table class="table">
                <thead class="thead-light">
                    <tr>
                    <th scope="col">Coach Number</th>
                    <th scope="col">Train Number</th>
                    <th scope="col">Train Name</th>
                    <th scope="col">Coach Type</th>
                    <th scope="col">Number of Available Seats</th>
                    <th scope="col">Number of Booked Seats</th>
                    </tr>
                    </thead><tbody>''' + st + '''</tbody></table>''' #pushing the body to a HTML table container
    return st #returning the table to be pushed in frontend





#api for booking seats by AI.
#abandoned but kept to showdown my work of logic to run the AI
@app.route('/seat/tobook', methods=['POST'])
def tobook():
    selectedinput = 0
    mongodb_client=pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    db=mongodb_client["Railway"] #pointing to the Railway database for operation
    coachCollection = db["Coaches"] #pointing to Coaches collection of Railway database
    trainCollection = db["Trains"] #pointing to Trains collection of Railway database
    ticketcollection = db["Tickets"] #pointing to Tickets collection of Railway database
    userCollection = db["users"] #pointing to users collection of Railway database
    user = userCollection.find_one({"ph_num":str(request.json["ph_num"]), "session":request.json["session"]}) #flagging the user supporting given session data
    if user == None: #if flag returns no document
        return "Please login as a user" #trigers frontend to forcefully redirect to login page after session storage clear
    else: #if flag returns a document
        cus_name = user["uname"] #getting the user name
        now = datetime.now(timezone("Asia/Kolkata")) #flagging the date and time data
        current_time = now.strftime("%H.%M") #crippling the data to a more refined approcach
        if request.json["istation"] == "Select a Station" or request.json["dstation"] == "Select a Station": #checking the veracity
            return "Source and Destination need to be selected."
        elif request.json["istation"] == request.json["dstation"]: #checking the veracity
            return "Source and destination can not be same."
        elif request.json["type"] == "Choose a type": #checking the veracity
            return "Please select a coach type."
        elif request.json["nos"] == None: #checing the veracity
            return "Number of seats can not be empty."
        elif request.json["nos"] < 1 or request.json["nos"] > 100: #checking the veracity
            return "Number of seats can not be out of this range - '1 to 100'"
        else: #if all values are ok and truthful
            isavailable = False #setting boolean false untill a coach is found to satisfy the seat needs of user
            trainsmatch = trainCollection.find({"istation":request.json["istation"], "dstation":request.json["dstation"]}) #getting all the trains runs between the two given station
            for train in trainsmatch: #for every train on these trains
                #converting database time into comparable format
                dtime = train["dtime"]
                if type(dtime) == float: #exception is int values
                    dtime = float(str(int(dtime)) + ".30")
                if float(current_time) < dtime: #if and only if the departure time is greater than the current time
                    selectedinput = train["dtime"]
                    isseat = coachCollection.find({"otsn":train["otsn"], "type":request.json["type"]}) #getting all the coach details associated with the train
                    #whilst the train is suitable, checking the coaches if any one of them have sufficient available seats
                    for c in isseat: #iterating through every coach in search of the coach where the requested seat is available
                        if c["noas"] < request.json["nos"]: #if not, ignore and continue the loop
                            continue
                        else: #if found double bound break to stop coach and train loop at once
                            isavailable = True #for breaking out of the outer loop
                            break
                if isavailable: #if previously coach found to be satisfying
                    break
            if selectedinput == 0: #if selectedinput is not changed 
                return "<h2>No train on this route is available for the day.</h2>"
            else: #if changed
                trainsmatch = trainCollection.find_one({ "istation":request.json["istation"], "dstation":request.json["dstation"], "dtime":selectedinput}) #getting the selected train by departure time
                coaches = coachCollection.find({"otsn":trainsmatch["otsn"], "type":request.json["type"]}) #getting all the coaches of the requested type of the train.
                for coach in coaches: #for every coaches of the train
                    if coach["noas"] >= request.json["nos"]: #while satisfies the seat requirement
                        coachCollection.update_one({"_id":coach["_id"]}, {"$inc":{"noas": -request.json["nos"], "nobs": +request.json["nos"]}}) #updating the coach details
                        coachno = coach["sn"] #getting the coach serail number
                        ttime = trainsmatch["dtime"] #getting the departure time from train document
                        bigquery = {"cus_name":cus_name, "coachno":coachno, "type":coach["type"], "nos":request.json["nos"], "otsn": trainsmatch["otsn"], "istation":request.json["istation"], "dstation":request.json["dstation"], "ph_num":request.json["ph_num"], "isvalid":True, "remarks":""} #composing the big query to insert new data in ticket collection
                        ticketcollection.insert_one(bigquery) #pushing new data to ticket collection
                        ticket = ticketcollection.find_one(bigquery) #getting the ticket information again to acquire the ObjectId
                        #converting time into readable format
                        if type(ttime) == float:
                            ttime = str(int(ttime)) + ".30"
                        else:
                            ttime = str(ttime) + ".00"
                        #sending user mail about ticket confirmation
                        subject = "Your ticket has been booked successfully"
                        body = "Hi! " + cus_name +". Your " + str(request.json["nos"])+ " seat(s) are booked at Coach No " + str(coachno) + " of " + str(request.json["type"])+ " type on " + str(trainsmatch["trainname"]) + " Train arriving at " + ttime + " . Your ticket number is " + str(ticket["_id"]) + "." + " Save it for further usage."
                        msg = EmailMessage()
                        msg["Subject"] = subject
                        msg["From"] = sender_email
                        msg["To"] = user["umail"]
                        msg.set_content(body)
                        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                            smtp.login(sender_email, password)
                            smtp.send_message(msg)
                        #returning the ticket confirmation message
                        return "Hi! " + cus_name +". Your " + str(request.json["nos"])+ " seat(s) are booked at Coach No " + str(coachno) + " of " + str(request.json["type"])+ " type on " + str(trainsmatch["trainname"]) + " Train arriving at " + ttime + " . Your ticket number is " + str(ticket["_id"]) + "." + " Save it for further usage."
                return "There is no available seat to book. Try booking after changing the type or reducing the seat number." #if selectedinput did trigger but no available type or required seats available






#api for booking train by time
@app.route('/seat/book', methods=['POST'])
def book():
    ticket = ""
    mongodb_client=pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    db=mongodb_client["Railway"] #pointing to the Railway database for operation
    coachCollection = db["Coaches"] #pointing to Coaches collection of Railway database
    trainCollection = db["Trains"] #pointing to Trains collection of Railway database
    ticketcollection = db["Tickets"] #pointing to Tickets collection of Railway database
    userCollection = db["users"] #pointing to users collection of Railway database
    time = request.json["time"] 
    time = time[:len(time)-8] #removing the O'clock section to perform operations on values
    #returns readable time to database like model to perform operations on
    time = float(time) #for neglecting the .30 
    if time != int(time): #if it comes with addional .30
        time = time + 0.20 
    user = userCollection.find_one({"ph_num":request.json["ph_num"], "session":request.json["session"]}) #getting the user information
    if user == None: #if no user available by the session
        return "session expired or user invalid! Please login again."
    elif request.json["time"] == "Choose": #checking the veracity
        return "Please choose time."
    elif request.json["type"] == "Choose a type": #checking the veracity
        return "Please choose coach type."
    elif request.json["nos"] == None: #checking the veracity
        return "Number of seats can not be empty."
    elif request.json["nos"] > 20 and request.json["nos"] < 1: #checking the veracity
        return "Number of seats must fall between 1 to 20"
    #if values are truthful
    train = trainCollection.find_one({"istation":request.json["istation"], "dstation":request.json["dstation"], "dtime":time}) #flagging the train with given source destination and departure time
    if train == None: #if no document is flagged 
        return "No train found or previous data changed."
    coaches = coachCollection.find({"otsn":train["otsn"], "type":request.json["type"]}) #flagging coaches associated with the train
    if coaches == None: #if no coached found
        return "No coach is available by this type."
    for coach in coaches: #if found atleast one
        #checking wheather the required number of seats available or not
        if coach["noas"] >= request.json["nos"]: #if satisfies
            ticketcollection.insert_one({"cus_name":user["uname"], "coachno":coach["sn"], "type":coach["type"], "nos":request.json["nos"], "otsn":coach["otsn"], "istation":train["istation"], "dstation":train["dstation"], "ph_num":int(user["ph_num"]), "time": request.json["time"], "isvalid":True, "remarks":""}) #generating new ticket with the data blocks
            coachCollection.update_one({"_id":coach["_id"]}, {"$inc":{"noas":-(request.json["nos"]), "nobs":request.json["nos"]}}) #update coaches available seats
            ticket = ticketcollection.find_one({"cus_name":user["uname"], "coachno":coach["sn"], "type":coach["type"], "nos":request.json["nos"], "otsn":coach["otsn"], "istation":train["istation"], "dstation":train["dstation"], "ph_num":int(user["ph_num"]), "isvalid":True, "remarks":""}) #getting the ticket information to get its ObjectId
            #sending user the ticket confirmation
            subject = "Your ticket has been booked successfully"
            body = "Hi! " + ticket["cus_name"] +". Your " + str(ticket["nos"])+ " seat(s) are booked at Coach No " + str(ticket["coachno"]) + " of " + str(ticket["type"])+ " type on " + str(train["trainname"]) + " Train arriving at " + request.json["time"] + " . Your ticket number is " + str(ticket["_id"]) + "." + " Save it for further usage."
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = sender_email
            msg["To"] = user["umail"]
            msg.set_content(body)
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                smtp.login(sender_email, password)
                smtp.send_message(msg)
            #composing return statement in case of successfull ticket reservation
            return "Hi! " + ticket["cus_name"] +". Your " + str(ticket["nos"])+ " seat(s) are booked at Coach No " + str(ticket["coachno"]) + " of " + str(ticket["type"])+ " type on " + str(train["trainname"]) + " Train arriving at " + request.json["time"] + " . Your ticket number is " + str(ticket["_id"]) + "." + " Save it for further usage."
        else: #if not satisfies, the loop keeps looking in other coach documents
            continue
    if ticket == "": #if the ticket variable is unchanged since the api call then 
        return "Number of seats requested is not available."





#api for fetching booked tickets     
@app.route('/ticketview', methods=['POST'])
def ticketview():
    st=""
    mongodb_client=pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    db=mongodb_client["Railway"] #pointing to the Railway database for operation
    ticketCollection = db["Tickets"] #pointing to Tickets collection of Railway database
    trainCollection = db["Trains"] #pointing to Trains collection of Railway database
    userCollection = db["users"] #pointing to users collection of Railway database
    user = userCollection.find_one({"ph_num":request.json["ph_num"], "session":request.json["session"]}) #checking for user session if it is still valid or not
    if user == None: #if not
        return "session expired or invalid user. Please login again." #triggers system force log in page after clearing session variable
    else: #if valid
        usertickets = ticketCollection.find({"ph_num":int(request.json["ph_num"])}) #getting all the tickets supporting the user phone number 
        for ticket in usertickets: #iterating every ticket
            trainname = trainCollection.find_one({"otsn":ticket["otsn"]}) #flagging the train for crippling the train information
            if trainname == None: #incase if the associated railbody is removed from database
                tname = "No Data in System" 
            else: #if exists
                tname = trainname["trainname"]
            #setting readable terms for the documents
            if ticket["isvalid"] == False:
                isvalid = "Invalid"
            else:
                isvalid = "Valid"
                #composing the table body
            st = st + "<tr><th scope='row'>" + str(ticket["_id"]) + "</th><td>" + tname + "</td><td>" + ticket["istation"] + "</td><td>" + ticket["dstation"] + "</td><td>" + ticket["time"] + "</td><td>" + str(ticket["otsn"]) + "</td><td>" + str(ticket["coachno"]) + "</td><td>" + ticket["type"] + "</td><td>" + str(ticket["nos"]) + "</td><td>" + isvalid + "</td><td>" + ticket["remarks"] + "</td></tr>"
        st = '''<table class="table">
                    <thead class="thead-light">
                        <tr>
                        <th scope="col">Ticket Number</th>
                        <th scope="col">Train Name</th>
                        <th scope="col">Initial Station</th>
                        <th scope="col">Destination Station</th>
                        <th scope="col">Departure time</th>
                        <th scope="col">Train No</th>
                        <th scope="col">Coach No</th>
                        <th scope="col">Coach Type</th>
                        <th scope="col">Seat(s)</th>
                        <th scope="col">Status</th>
                        <th scope="col">Remarks<th>
                        </tr>
                        </thead><tbody>''' + st + '''</tbody></table>''' #embedding ticket body in html fashion
        return st #being returned to be pushed in frontend





#api for user ticket cancel
@app.route('/ticketcancel', methods=['PUT'])
def cancelticket():
    mongodb_client=pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    db=mongodb_client["Railway"] #pointing to the Railway database for operation
    ticketCollection = db["Tickets"] #pointing to Tickets collection of Railway database
    coachCollection = db["Coaches"] #pointing to Coaches collection of Railway database
    userCollection = db["users"] #pointing to users collection of Railway database
    user = userCollection.find_one({"ph_num": request.json["ph_num"], "session":request.json["session"]}) #checking is the session is still active or not
    userp = userCollection.find_one({"ph_num": request.json["ph_num"], "upass":encryptpassword(request.json["upass"])}) #checking the 2 factor login is legit or not
    if user == None: #if session invalid
        return "session expired or invalid user. Please login again."
    elif userp == None: #id password incorrect
        return "Credentials doesn't match, Try resetting your password."
    else: #if session and password is truthful
        quesrytorun = {"ph_num":int(user["ph_num"]), "_id":ObjectId(request.json["ticketno"])} #setting query to use multiple times
        ticket = ticketCollection.find_one(quesrytorun) #geting the ticket information 
        if ticket == None: #if not ticket found by the query
            return "ticket number doesn't match any record."
        elif ticket["isvalid"] == False: #if found but it is already been cancelled
            return "Ticket is already " + str(ticket["remarks"])
        else: #ticket found bt not already cancelled
            ticketCollection.update_one(quesrytorun, {"$set":{"remarks":"Cancelled By User.", "isvalid":False}}) #changing the ticket validity
            coachCollection.update_one({"sn":ticket["coachno"]}, {"$inc":{"noas": +ticket["nos"], "nobs": -ticket["nos"]}}) #changing the coach seat information
            #sending ticket cancellation confirmation via mail
            subject = "Your ticket has been cancelled successfully"
            body = "Hello " + str(ticket["cus_name"]) + "! Ticket no - " + str(ticket["_id"]) + " of your reservation on from " + str(ticket["istation"]) + " to " + str(ticket["dstation"]) + " train has been cancelled successfully."
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = sender_email
            msg["To"] = user["umail"]
            msg.set_content(body)
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                smtp.login(sender_email, password)
                smtp.send_message(msg)
            #returning the system message
            return "Hello " + str(ticket["cus_name"]) + "! Your ticket has been cancelled successfully."





#api for getting train time by stations
@app.route('/seat/gettime', methods=['POST'])
def gettime():
    st = ""
    mongodb_client=pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    db=mongodb_client["Railway"] #pointing to the Railway database for operation
    trainCollection = db["Trains"] #pointing to Trains collection of Railway database
    if request.json["istation"] == "Select a Station" or request.json["dstation"] == "Select a Station": #checking the veracity
        return "<h6 class='display-6'>Initial and destination station must be chosen</h6>"
    elif request.json["istation"] == request.json["dstation"]: #checking the veracity
        return "<h6 class='display-6'>Source and destination can not be same</h6>"
    else: #if data is truthful and operationalble
        trains = trainCollection.find({"istation":request.json["istation"], "dstation":request.json["dstation"]}) #getting all train documents that runs between these two stations
        if trains == None: #if no trains found
            return "<h6 class='display-6'>No train available.</h6>"
        for train in trains: #if atleast one train document available
            #converting times into readable format to be used in table
            if type(train["dtime"]) == float:
                time = str(int(train["dtime"] - 0.5)) + ".30 O'clock" 
            else:
                time = str(train["dtime"]) + ".00 O'clock"
            st = st + "<option>" + time + "</option>" #composing table body
        st = '''<label for="time" class="col-md-4 col-form-label text-md-right display-1"><b>Departure Time</b></label>
                <div class="col-md-6">
                <select id='time' name='time'  class="form-control form-select form-select-lg mb-3" required>
                    <option selected disabled hidden>Choose</option>''' + st + '''</select></div>''' #embedding the table in HTML fashion
        return st #returning to push into frontend





#~~~~~~~~~~~~~~~~~~~~~~~GENERAL-APIS~~~~~~~~~~~~~~~~~~~~~~~

#api for fetching uniformed time table
@app.route('/time_table', methods=['GET'])
def timetable():
    st = ""
    mongodb_client=pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    db=mongodb_client["Railway"] #pointing to the Railway database for operation
    trainCollection = db["Trains"] #pointing to Trains collection of Railway database
    start = 1 #for serialization
    trains = trainCollection.find({}) #getting all train documents 
    for train in trains: #interating each train and collecting data for table body
        #converting database time in readable format
        if type(train["dtime"]) == float:
            dep_time = str(int(train["dtime"] - 0.5)) + ".30" 
        else:
            dep_time = str(train["dtime"]) + ".00"
        #composing the table body content over iterations
        st = st + "<tr><td>" + str(start) + "</td><td>" + str(train["otsn"]) + "</td><td>" + train["trainname"] + "</td><td>" + train["istation"] + "</td><td>" + dep_time + "</td><td>" + train["dstation"] + "</td><td>" + str(float(dep_time) + 1) + str(0) + "</td><td>" + str(train["noc"]) + "</td></tr>"
        start = start + 1
    st = '''<table class="table table-striped">
                <thead>
                <tr>
                    <th>Serial No</th>
                    <th>Train No</th>
                    <th>Train Name</th>
                    <th>Source Station</th>
                    <th>Departure Time</th>
                    <th>Destination Station</th>
                    <th>Arrival Time</th>
                    <th>Number of Coaches</th>
                </tr></thead><tbody>''' + st +'''</tbody>
            </table>''' #embedding table body in html to be pushed
    return st #sent to frontend to be pushed





#api for automatically resettng OTP after 3 minutes
@app.route('/resetotp', methods=['POST'])
def resetotp():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    details = railwaydb[request.json["collection"]] #pointing to given collection of Railway database
    password = encryptpassword(request.json["pass"]) #encrypting password for database comparison
    details.update_one({request.json["wid"]:request.json["id"], request.json["wpass"]:password}, {"$set":{"myotp":""}}) #resetting otp
    return "OTP expired, Acquire a new one." #system display





#api for posting feedback in the system [disabled for the final system]       
@app.route('/wrtous', methods=['POST'])
def feedback():
    mongodb_client = pymongo.MongoClient(connection_sent) #estabilishing connection to MongoDB database after getting value from credentials
    railwaydb = mongodb_client["Railway"] #pointing to the Railway database for operation
    fdetails = railwaydb["feedbacks"] #pointing to feedback collection of Railway database
    fdetails.insert_one({"cname":request.json["cname"], "feedback": request.json["feedback"]}) #inserting new data to feedbacks collection
    #sending to superadmin as feedback alert
    subject = "Feedback Alert!"
    body = request.json["cname"] + "just posted a feedback \n\n '" + request.json["feedback"] + "'"
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = "luciefer9062hurley@gmail.com"
    msg.set_content(body)
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(sender_email, password)
        smtp.send_message(msg)
    return "Hello! " + request.json["cname"] + " your feedback has been successfully captured." #system message

if __name__ == "__main__":
    app.run(debug=True)

#Contact - Tusher Mondal[luciefer9062hurley@gmail.com] or Aniket Sarkar[aniketkolkata24@gmail.com] if you have any query
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! END !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#
