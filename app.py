# Any an all imports always go at the top of the file
from flask import Flask, jsonify, request, abort
from flask_sqlalchemy import SQLAlchemy 
from flask_marshmallow import Marshmallow
from marshmallow.validate import Length
from sqlalchemy import Column, Integer, String, Float, Date, ForeignKey, create_engine
from datetime import date
# import psycopg2 # to connect database to flask
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
from flask_bcrypt import Bcrypt
from marshmallow import fields
import os
from sqlalchemy.orm import sessionmaker

# from myapp.models import User  # import the User model from your app
from flask_sqlalchemy import SQLAlchemy 
# set the database URI via SQLAlchemy, 



# Create a database connection
engine = create_engine('postgresql://db_dev:123456@localhost:5432/trello_clone_db')
Session = sessionmaker(bind=engine)
session = Session()



# Configuration


app = Flask(__name__)
# set the database URI via SQLAlchemy, 
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql+psycopg2://db_dev:123456@localhost:5432/trello_clone_db"

# to avoid the deprecation warning
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# register a secret key in the app configuration
app.config["JWT_SECRET_KEY"] = "Backend best end" 
# in productin the key needs to be get from an environment variable

class Config(object):
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # access to .env and get the value of SECRET_KEY, the variable name can be any but needs to match
    JWT_SECRET_KEY =  os.environ.get("SECRET_KEY")
    JSON_SORT_KEYS=False



# create the database object
db = SQLAlchemy(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

## endpoints

# create app's cli command named create, then run it in the terminal as "flask create", 
# it will invoke create_db function
@app.cli.command("create")
def db_create():
    db.create_all()
    print("Tables created")

# destroy DB
@app.cli.command('drop')
def db_drop():
    db.drop_all()
    print('Tables dropped')



@app.cli.command("seed")
def db_seed():
    admin_user = User(
        email = "admin@email.com",
        password = bcrypt.generate_password_hash("password123").decode("utf-8"),
        admin = True
    )
    db.session.add(admin_user)

    user1 = User(
        email = "user1@email.com",
        password =  bcrypt.generate_password_hash("123456").decode("utf-8")
    )
    db.session.add(user1)
    db.session.commit()
    # create the first card object
    card1 = Card(
        # set the attributes, not the id, SQLAlchemy will manage that for us
                title = "Start the project",
                description = "Stage 1, creating the database",
                status = "To Do",
                priority = "High",
                date = date.today(),
                user_id = user1.id
                )
    # Add the object as a new row to the table
    db.session.add(card1)
    
    # create the second card object
    card2 = Card(
        # set the attributes, not the id, SQLAlchemy will manage that for us
        title = "SQLAlchemy and Marshmallow",
        description = "Stage 2, integrate both modules in the project",
        status = "Ongoing",
        priority = "High",
        date = date.today(),
        # it also can be done this way
        user = user1
    )
    # Add the object as a new row to the table
    db.session.add(card2)
    db.session.commit()
    
   



    comment1 = Comment(
        # set the attributes, not the id, SQLAlchemy will manage that for us
        message = "Created the database and users in PostgreSQL ",
        user = user1,
        card = card1
    )
    # Add the object as a new row to the table
    db.session.add(comment1)

    comment2 = Comment(
        message = "Make sure you check the database authentication",
        user = admin_user,
        card = card1
    )
    # Add the object as a new row to the table
    db.session.add(comment2)

    comment3 = Comment(
        message = "Go to the official documentation when errors",
        user = user1,
        card = card2
    )
    # Add the object as a new row to the table
    db.session.add(comment3)


    # commit the changes
    db.session.commit()
    print("Table seeded") 
    
# get all cards
@app.route("/get_cards", methods=["GET"])
def get_cards():
    # get all the cards from the database table
    cards_list = Card.query.all()
    # Convert the cards from the database into a JSON format and store them in result
    result = cards_schema.dump(cards_list)
    # return the data in JSON format
    return jsonify(result)

# Register new user
@app.route("/auth/register", methods=["POST"])
def auth_register():
    #The request data will be loaded in a user_schema converted to JSON. request needs to be imported from
    user_fields = user_schema.load(request.json)
     # find the user
    user = User.query.filter_by(email=user_fields["email"]).first()

    if user:
        # return an abort message to inform the user. That will end the request
        return abort(400, description="Email already registered")

    #Create the user object
    user = User()
    #Add the email attribute
    user.email = user_fields["email"]
    # user.password = user_fields["password"]
    #Add the password attribute hashed by bcrypt
    user.password = bcrypt.generate_password_hash(user_fields["password"]).decode("utf-8")
    #Add it to the database and commit the changes
    user.admin = False  # false by default, not every user can be admin
    db.session.add(user)
    db.session.commit()

    #create a variable that sets an expiry date
    expiry = timedelta(days=1)
    #create the access token
    access_token = create_access_token(identity=str(user.id), expires_delta=expiry)
    # return the user email and the access token
    return jsonify({"user":user.email,  "user_id": user.id, "token": access_token })





    #Return the user to check the request was successful
    # return jsonify(user_schema.dump(user))


#routes declaration area, below /auth/register
@app.route("/auth/login", methods=["POST"])
def auth_login():
    #get the user data from the request
    user_fields = user_schema.load(request.json)
    #find the user in the database by email
    user = User.query.filter_by(email=user_fields["email"]).first()
    # there is not a user with that email or if the password is no correct send an error
    if not user or not bcrypt.check_password_hash(user.password, user_fields["password"]):
        return abort(401, description="Incorrect username and password")
    
    # return jsonify(message='Login suceeded'), 200
    
    #create a variable that sets an expiry date
    expiry = timedelta(days=1)
    #create the access token
    access_token = create_access_token(identity=str(user.id), expires_delta=expiry)
    # return the user email and the access token
    return jsonify({"user":user.email, "token": access_token, "user_id": user.id })

# display current user
@app.route("/user", methods=["GET"])
@jwt_required()
def current_user():
    user_id  = get_jwt_identity()
    user = User.query.get(user_id)
    # return jsonify({ "user_id": user_id })
    return jsonify({"user":user.email,  "user_id": user.id, "admin": user.admin })

@app.route("/cards", methods=["POST"])
#Decorator to make sure the jwt is included in the request
@jwt_required()
def card_create():
    #Create a new card
    card_fields = card_schema.load(request.json)

    # get the id from jwt
    user_id = get_jwt_identity()
    new_card = Card()
    new_card.title = card_fields["title"]
    new_card.description = card_fields["description"]
    new_card.status = card_fields["status"]
    new_card.priority = card_fields["priority"]
    # new_card.user_id = get_jwt_identity()
    
    # not taken from the request, generated by the server
    new_card.date = date.today()
    # add to the database and commit
     # Use that id to set the ownership of the card
    new_card.user_id = user_id

    db.session.add(new_card)
    db.session.commit()
    #return the card in the response
    return jsonify(card_schema.dump(new_card))

    #add the id to let the server know the card we want to delete
@app.route("/del_cards/<int:id>", methods=["DELETE"])
@jwt_required()
#Includes the id parameter
def card_delete(id):
    #get the user id invoking get_jwt_identity
    user_id = get_jwt_identity()
    #Find it in the db
    user = User.query.get(user_id)
    #Make sure it is in the database
    if not user:
        return abort(401, description="Invalid user")
    # Stop the request if the user is not an admin
    if not user.admin:
        return abort(401, description="Unauthorised user")

    # find the card
    card = Card.query.filter_by(id=id).first()
    # card = Card.query.get(id)
    #return an error if the card doesn't exist
    if not card:
        return abort(400, description= "Card doesn't exist")
    #Delete the card from the database and commit
    db.session.delete(card)
    db.session.commit()
    #return the card in the response
    return jsonify(card_schema.dump(card))


@app.route("/users", methods=["GET"])
def get_users():
    # get all the users from the database table
    users_list = User.query.all()
    # Convert the users from the database into a JSON format and store them in result
    result = users_schema.dump(users_list)
    # return the data in JSON format
    return jsonify(result)


#POST a new comment
@app.route("/<int:id>/comments", methods=["POST"])
# logged in user required
@jwt_required()
# Card id required to assign the comment to a car
def post_comment(id):
    # #Create a new comment
    comment_fields = comment_schema.load(request.json)

    #get the user id invoking get_jwt_identity
    user_id = get_jwt_identity()
    #Find it in the db
    #user = User.query.get(user_id)
    user = session.get(User, user_id)
    #Make sure it is in the database
    if not user:
        return abort(401, description="Invalid user")

    # find the card
    card = Card.query.filter_by(id=id).first()
    #return an error if the card doesn't exist
    if not card:
        return abort(400, description= "Card does not exist")
    #create the comment with the given values
    new_comment = Comment()
    new_comment.message = comment_fields["message"]
    # Use the card gotten by the id of the route
    new_comment.card = card
    # Use that id to set the ownership of the card
    new_comment.user_id = user_id
    # add to the database and commit
    db.session.add(new_comment)
    db.session.commit()
    #return the card in the response
    return jsonify(card_schema.dump(card))

## Models

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(), nullable=False, unique=True)
    password = db.Column(db.String(), nullable=False)
    admin = db.Column(db.Boolean(), default=False)
    # add the relationships to the Card and User model
    cards = db.relationship(
        "Card",
        backref="user",
        cascade="all, delete"
    )
    comments = db.relationship(
        "Comment",
        backref="user",
        cascade="all, delete"
    )


class Card(db.Model):
    # define the table name for the db
    __tablename__= "cards"
    # Set the primary key, we need to define that each attribute is also a column in the db table, remember "db" is the object we created in the previous step.
    id = db.Column(db.Integer,primary_key=True)
    # Add the rest of the attributes. 
    title = db.Column(db.String())
    description = db.Column(db.String())
    status = db.Column(db.String())
    priority = db.Column(db.String())
    date = db.Column(db.Date())
    # Also add the relationships to the Card and User model:
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    comments = db.relationship(
        "Comment",
        backref="card",
        cascade="all, delete"
        )





class Comment(db.Model):
    # define the table name for the db
    __tablename__= "comments"

    id = db.Column(db.Integer,primary_key=True)
    # Add the rest of the attributes. 
    message= db.Column(db.String())
    # two foreign keys
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    card_id = Column(Integer, ForeignKey("cards.id"), nullable=False)




## Schemas

#create the Card Schema with Marshmallow, it will provide the serialization needed for converting the data into JSON
class CardSchema(ma.Schema):
    class Meta:
        ordered = True # show the columns in the right order instead of alphabetically
        # Fields to expose
        fields = ("id", "title", "description", "date", "status", "priority", "user", "comments")
    user =  fields.Nested("UserSchema", only=("email",))   
    comments = fields.List(fields.Nested("CommentSchema"))

#single card schema, when one card needs to be retrieved
card_schema = CardSchema()
#multiple card schema, when many cards need to be retrieved
cards_schema = CardSchema(many=True)

class UserSchema(ma.Schema):
    class Meta:
        # model = User
        
        fields = ['cards','id', 'email', 'password', 'admin']
        load_only = ['password', 'admin'] # this will not show up when invoke dump to retrieve data
    #set the password's length to a minimum of 6 characters
    password = ma.String(validate=Length(min=6))
    cards = fields.List(fields.Nested( "CardSchema", exclude=("user",)))

user_schema = UserSchema()
users_schema = UserSchema(many=True)

class CommentSchema(ma.Schema):
    class Meta:
        ordered = True
        # Fields to expose. Card is not included as comments will be shown always attached to a Card.
        fields = ("id", "message", "user")
    user =  fields.Nested("UserSchema", only=("email",))  
      
comment_schema = CommentSchema()

comments_schema = CommentSchema(many=True)


if __name__ == '__main__':
    app.run()