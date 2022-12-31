#Topic = Libraries#
---
**Context** - Pytz
Pytz - Python Time Zone [ World Timezone Definitions for Python ]
The Library is used to mark up the exact time stamps while a entity is trying to make a change to the system.
Ex - The time when an Admin logs in.
More detailed information on Pytz can be found here - [title](https://pypi.org/project/pytz/)

**Context** - datetime
datetime - Basic date and time types [ package where date and time can be operable ]
The library is used to store the last change of the system. It helps keeping track of the progress, whilst comparing local branch to the master.
More detailed information can be found here - [title](https://docs.python.org/3/library/datetime.html)

**Context** - Flask
Flask - Flask is considered more Pythonic than the Django web framework because in common situations the equivalent Flask web application is more explicit. Flask is also easy to get started with as a beginner because there is little boilerplate code for getting a simple app up and running.
Flask has many configuration values, with sensible defaults, and a few conventions when getting started. By convention, templates and static files are stored in subdirectories within the application’s Python source tree, with the names templates and static respectively. While this can be changed, you usually don’t have to, especially when getting started.
It is the main frame from where our backend starts.
More detailed information can be found here - [title](https://flask.palletsprojects.com/en/2.1.x/)

**Context** - Pymongo
Pymongo - Detailed library of python to connect control and drive a MongoDB asset
By using this library we can perform CRUD operations on our MongoDB database.
It is a secure way to connect a single entity at a singular time to the Database to avoid severe duplication, as many operation can take place at the same time.
More detailed information can be found here - [title](https://pymongo.readthedocs.io/en/stable/)

**Context** - bson
bson - Binary Javascript Object Notation
It is a binary-encoded serialization of JSON documents. BSON has been extended to add some optional non-JSON-native data types, like dates and binary data. BSON can be compared to other binary formats, like Protocol Buffers.
We used Bson to decrypt the ObjectId data from ticket collection to serve the number as ticket because it is unique for every document.
More detailed information can be found here - [title](https://pymongo.readthedocs.io/en/stable/api/bson/index.html)

**Context** - Flask-CORS
Flask-CORS is a cross origin resource sharing paradigm of Flask applications.
By applying CORS policy we made sure that out backend is only available to out frontend requests. And It is responsive to the same origin even its multiple times.
More detailed information can be found here - [title](https://flask-cors.readthedocs.io/en/latest/)

**Context** - email.message
EmailMessage dictionary-like interface is indexed by the header names, which must be ASCII values. The values of the dictionary are strings with some extra methods. Headers are stored and returned in case-preserving form, but field names are matched case-insensitively. Unlike a real dict, there is an ordering to the keys, and there can be duplicate keys. Additional methods are provided for working with headers that have duplicate keys.
Further all use used this library to send text via SMTP server.
More detailed information can be found here - [title](https://docs.python.org/3/library/email.message.html)

**Context** - smtplib
smtplib is used to make a secure connection to email server(e.g mail.google.com) via smtp protocol.
With some direction, our system sends automated OTP, alerts, updated to user mail at ease. As the threading is very much adaptable, it is possible now to send multiple mails at the same time.
More detailed information can be found here - [title](https://docs.python.org/3/library/smtplib.html)

**Context** - base64
base64 library is a unique encryption and decryption engine on python.
The password and other sensitive detail our website captures from users are very valuable and must be kept and stored securely. As a responsible database administrator our approach of using base64 to encrypt passwords for keeping in databases
More detailed information can be found here - [title](https://docs.python.org/3/library/base64.html)

**Context** - json
Json - JavaScript Object Notation
Using json library we can cripple multiple data in key value pairs and propagate through different apis or frontend to backend nad viceversa.
Json is the hashlike data notation where the properties are the same as Hashmap but it has encoders and decoders by default to protect the data for non Json object receivers.
More detailed information can be found here - [title](https://docs.python.org/3/library/json.html)

**Context** - secrets
This library is just used for generating random strings to use this as a session data. This helped the authentication to be more secure and flexible.
More detailed information can be found here - [title](https://docs.python.org/3/library/secrets.html)




#Topic = credentials#

**The credentials Object**
To make the system work we had to setup some credentials for email, mongoDB connection, password, origin information etc.
Hardcoding these kind of information is not professional and is not recommended as it may show vulnerability.
So we saved every bit of secure information as key value pairs in JSON object and imported it to inherit the information.
That way our credentials become secured and backend more achieving or apealing.
