from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, validators, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date
from wtforms.widgets import TextArea
from flask_login import UserMixin, login_user,LoginManager, login_required, logout_user, current_user


#create a Flask Instance
app = Flask(__name__)
# Add Database SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# Add Database MySQL ='mysql://username:password@localhost/db_name' - ADDED '+pymysql'
#app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://root:july2021_@localhost/our_users"
# create a Secret Key = Put it in a config file later
app.config['SECRET_KEY'] = "my super secret key that no one shoud know"
# Initialize the Database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Flask_Login Stuff
login_manager = LoginManager() # instantiates Flask login manager
login_manager.init_app(app) # pass the app into the login manager
login_manager.login_view = 'login'

@login_manager.user_loader # loads the user when we are logging in
def load_user(user_id): # we need to pass user id
	return Users.query.get(int(user_id)) #to get the user id we need to query






# Create Login Form
class LoginForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()])
	password = PasswordField("Password", validators=[DataRequired()])
	submit = SubmitField("Sumbit")

# Create Log In Page
@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit(): # validate the form if submitted
		user = Users.query.filter_by(username=form.username.data).first() #looks up the username of the form in the DB and grabs the first one if it exists
		if user:
			# Check the Hash
			if check_password_hash(user.password_hash, form.password.data):
				login_user(user) #log in, create sessions etc.
				flash("Login Successfull!")
				return redirect(url_for('dashboard'))
			else:
				flash("Wrong Password - Try Again!")
		else: # if there is not a user
			flash("That User Doesn't Exist!  Try Again...")

	return render_template('login.html', form=form)

# Create Logout Route and Function
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	flash("You Have Been Logged Out! Thanks For Stopping By...")
	# we want to return redirect somewhere...
	return redirect(url_for('login'))




# Create Dashboard Page
@app.route('/dashboard', methods= ['GET', 'POST'])
@login_required # if we go straight to dashboard it redirects us to the login page
def dashboard():
	form = UserForm()
	id = current_user.id
	name_to_update = Users.query.get_or_404(id) # create a variable to update and assigns all data from the 'id' record to it
	if request.method == 'POST':
		name_to_update.name = request.form['name'] #this sets 'name' attribute of the variable (a record in the db) to the 'name' attribute submitted through the form
		name_to_update.email = request.form['email']
		name_to_update.favorite_color = request.form['favorite_color']
		name_to_update.username = request.form['username']
		# a person fills the form, the data gets passed into the variables
		# now we want to save them to the Database
		try:
			db.session.commit() # saves the data from variables into the DB
			flash("User Updated Successfully!")
			# выдаем сновую траницу с формой и значением переменной name_to_update = все данные о человеке
			return render_template("dashboard.html",
				form=form,
				name_to_update=name_to_update)
		except:
			flash("Error! Looks like there was a problem... try again!")
			return render_template("dashboard.html",
				form=form,
				name_to_update=name_to_update)
	else:
		return render_template("dashboard.html",
				form=form,
				name_to_update=name_to_update,
				id = id
				)
	return render_template('dashboard.html')


# Create a Blog Post Model
class Posts(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(255))
	content = db.Column(db.Text)
	author = db.Column(db.String(255))
	date_posted = db.Column(db.DateTime, default=datetime.utcnow)
	slug = db.Column(db.String(255))

# Create a Post Form
class PostForm(FlaskForm):
	title = StringField("Title", validators=[DataRequired()])
	content = StringField("Content", validators=[DataRequired()], widget=TextArea())
	author = StringField("Author", validators=[DataRequired()])
	slug = StringField("Slug", validators=[DataRequired()])
	submit = SubmitField("Submit")

@app.route('/posts/delete/<int:id>')
def delete_post(id):
	post_to_delete = Posts.query.get_or_404(id)
	# we grabbed the post with some id from the DB
	# now we want to delete it

	try:
		db.session.delete(post_to_delete)
		db.session.commit()
		# show a message
		flash("Blog Post Was Deleted!")

		# grab all posts and redirect to the posts page again
		posts = Posts.query.order_by(Posts.date_posted)
		return render_template("posts.html", posts=posts) #pass to the webpage

		# if something goes wrong:
	except:
		flash('Whoops! There Was a Problem Deleting... Try again..')
		# grab all posts and redirect to the posts page again
		posts = Posts.query.order_by(Posts.date_posted)
		return render_template("posts.html", posts=posts) #pass to the webpage



@app.route('/posts')
def posts():
	# Grab all the Posts from the Database
	posts = Posts.query.order_by(Posts.date_posted)
	return render_template("posts.html", posts=posts) #pass to the webpage

@app.route('/posts/<int:id>')
def post(id):
	post = Posts.query.get_or_404(id)
	return render_template('post.html', post=post)

@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
	post = Posts.query.get_or_404(id) # Find the Post
	form = PostForm() # Create form instance assign to a variable
	if form.validate_on_submit(): # is someone just viewing or submitting data?
		post.title = form.title.data # assign sumbitted data to a variable
		post.author = form.author.data 
		post.slug = form.slug.data 
		post.content = form.content.data
		# so, we grabbed all of that stuff from the form
		# now we want to commit all of it to the Database/Update DB
		db.session.add(post) # post is all of the above data now
		db.session.commit()

		# flash a message
		flash("Post Has Been Updated!")
		# return this to the individual blog post page by redirecting
		# instead of by rendering the page (our usual way)
		return redirect(url_for('post', id=post.id)) #need to import redirect and url_for

# shows the page filled out with previous info so we dont have to retype it
	form.title.data = post.title
	form.author.data = post.author
	form.slug.data = post.slug
	form.content.data = post.content
	return render_template('edit_post.html', form=form)
	# question is can we have this block of code before the if statement?




# Add Post Page
@app.route('/add-post', methods=['GET', 'POST'])
#@login_required
def add_post():
	form = PostForm()

	if form.validate_on_submit():
		post = Posts(title=form.title.data, 
			content=form.content.data, 
			author=form.author.data, 
			slug=form.slug.data)
		# Clear The Form
		form.title.data = ''
		form.content.data = ''
		form.author.data = ''
		form.slug.data = ''

		# Add Post Data To The Database
		db.session.add(post)
		db.session.commit()

		# Return A Message
		flash("Blog Post Submitted Successfully!")

	# Redirect to the webpage  (do this outside the IF statement)
	# we have not created the html page yet
	return render_template("add_post.html", form=form)

# Creat a Json thing - a webpage that will return Json
@app.route('/date')
def get_current_date():
	favorite_pizza = {
	"Lisa": "Pepperoni",
	"Vasya": "Cheese",
	"Vanya": "Mushroom"
	}
	return favorite_pizza
	#return {"Date": date.today()} # Python dictionary returns Json
	# Flask will jsonifies anything for you





# Create a Model
class Users(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), nullable=False, unique=True)
	name = db.Column(db.String(200), nullable=False)
	email = db.Column(db.String(120), nullable=False, unique=True)
	favorite_color = db.Column(db.String(120))
	date_added = db.Column(db.DateTime, default=datetime.utcnow)
	# Do some password stuff!
	password_hash = db.Column(db.String(120))

	@property
	def password(self):
		raise AttributeError("password is not a readable attribute!")

	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)
	
	# Create a String
	def __repr__(self):
		return '<Name %r>' % self.name



class UserForm(FlaskForm):
	name = StringField("Name", validators=[DataRequired()])
	username = StringField("Username", validators=[DataRequired()])
	email = StringField("Email", validators=[DataRequired()])
	favorite_color = StringField("Favorite Color")
	password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo('password_hash2', message='Passwords Must Match!')])
	password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()] )
	submit = SubmitField("Sumbit")

@app.route('/delete/<int:id>')
def delete(id):
	user_to_delete = Users.query.get_or_404(id)
	name = None
	form = UserForm()
	try:
		db.session.delete(user_to_delete)
		db.session.commit()
		flash('User Deleted Successfully!!')

		our_users = Users.query.order_by(Users.date_added)
		return render_template("add_user.html",
			form=form,
			name=name,
			our_users=our_users)

	except:
		flash('Whoops! There was a problem deleting User, try again..')
		return render_template("add_user.html",
			form=form,
			name=name,
			our_users=our_users)
	

# Update Database Record:
@app.route('/update/<int:id>', methods =['GET', 'POST']) # we identify a record by its id
def update(id): # we pass in 'id' from the url 
	form = UserForm()
	name_to_update = Users.query.get_or_404(id) # create a variable to update and assigns all data from the 'id' record to it
	if request.method == 'POST':
		name_to_update.name = request.form['name'] #this sets 'name' attribute of the variable (a record in the db) to the 'name' attribute submitted through the form
		name_to_update.email = request.form['email']
		name_to_update.favorite_color = request.form['favorite_color']
		name_to_update.username = request.form['username']
		# a person fills the form, the data gets passed into the variables
		# now we want to save them to the Database
		try:
			db.session.commit() # saves the data from variables into the DB
			flash("User Updated Successfully!")
			# выдаем сновую траницу с формой и значением переменной name_to_update = все данные о человеке
			return render_template("update.html",
				form=form,
				name_to_update=name_to_update)
		except:
			flash("Error! Looks like there was a problem... try again!")
			return render_template("update.html",
				form=form,
				name_to_update=name_to_update)
	else:
		return render_template("update.html",
				form=form,
				name_to_update=name_to_update,
				id = id
				)
# Creat A Password Form
class PasswordForm(FlaskForm):
	email = StringField("What's Your Email?", validators=[DataRequired()])
	password_hash = PasswordField("What's your password?", validators=[DataRequired()])
	submit = SubmitField("Sumbit")

# Create a Form Class
class NamerForm(FlaskForm):
	name = StringField("What's Your Name?", validators=[DataRequired()])
	submit = SubmitField("Sumbit")
	#there is a big list of types of fields and validators validating different things



#create a route decorator


# def index():
# 	return "<h1>Hello, World!</h1>"

# FILTERS:
# safe
# capitalize
# lower
# upper
# title
# trim
# strinptags
@app.route('/')
def index():
	first_name = "Misha"
	stuff = 'This is bold text'
	#flash("Добро пожаловать на мой сайт!")

	favorite_pizza =['Pepperoni',
	'Mushrooms',
	'3 cheeses',
	41]
	return render_template('index.html', 
		first_name=first_name,
		stuff=stuff,
		favorite_pizza=favorite_pizza)

# localhost:5000/user/Mikhail
@app.route('/user/<name>') #pulls the name of an url

def user(name): #passes the name into a function
	return render_template('user.html', user_name=name)
	#return "<h1>Hello, {}!!!</h1>".format(name) #prints the name onto a webpage
	#{% endif %} #orange = variable name in Jinja2 template, white = variable name in py file.

#Invalid URL
@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

#Internal Server Error
@app.errorhandler(500)
def page_not_found(e):
	return render_template('500.html'), 500


#Create Password Test Page
@app.route('/test_pw', methods=['GET', 'POST'])
def test_pw():
	email= None
	password = None
	pw_to_check = None
	passed = None
	form = PasswordForm()

	# Validate Form
	if form.validate_on_submit():
		email = form.email.data #assign variable name to the submitted data
		password = form.password_hash.data
		#clear it for the next time
		form.email.data = '' 
		form.password_hash.data = ''

		#  Look up User by Email Address
		# we fill the form with user email and open the db and check the first
		# result
		# if it exists it will return this:
		pw_to_check = Users.query.filter_by(email=email).first()

		# Check Hashed-Password, it returns True/False, we create a variable for that
		passed = check_password_hash(pw_to_check.password_hash, password)

	return render_template('test_pw.html',
		email = email, #field/variable email in the form at test_pw.html = this function's variable email
		password = password, #field/variable password in the form = this function's variable "password"
		pw_to_check=pw_to_check, # pass this variable onto the page
		passed=passed,
		form=form) # form on the test_pw.html page = this function's variable form which is = to PasswordForm 
					#defined earlier and is an instance of the Flask Form class
		



# Create Add User page and save data to the Database
@app.route('/user/add', methods = ['GET', 'POST'])
def add_user():
	name = None
	form = UserForm()
	if form.validate_on_submit():
		user = Users.query.filter_by(email=form.email.data).first()
		if user is None:
			# Hash password
			hashed_pw = generate_password_hash(form.password_hash.data, 'sha256')
			user = Users(username=form.username.data, name=form.name.data, email=form.email.data, favorite_color=form.favorite_color.data, password_hash=hashed_pw)
			db.session.add(user)
			db.session.commit()
		name = form.name.data
		form.name.data = ''
		form.username.data = ''
		form.email.data = ''
		form.favorite_color.data = ''
		form.password_hash = ''

		flash("User Added Successfully!")
	our_users = Users.query.order_by(Users.date_added)
	return render_template('add_user.html', 
		form=form, 
		name=name,
		our_users=our_users)


# Create Name Page
@app.route('/name', methods=['GET', 'POST'])
def name():
	name = None
	form = NamerForm()
	# Validate Form
	if form.validate_on_submit():
		name = form.name.data
		form.name.data = ''
		flash("Form Submitted Successfully!")
		
	return render_template("name.html", 
		name = name,
		form = form)




