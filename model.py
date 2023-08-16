from mongoengine import *

import os
from dotenv import load_dotenv
load_dotenv()

connection_string = os.getenv("CONNECT_STRING")

class User(Document):
    id = SequenceField(primary_key = True)
    username = StringField()
    email = StringField()
    password = StringField()
