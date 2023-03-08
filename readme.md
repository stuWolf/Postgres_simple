mkdir postgreSQL_ed && cd postgreSQL_ed

virtualenv venv && source venv/bin/activate
git init && echo 'venv/' > .gitignore
pip install Flask

pip freeze > requirements.txt

Create DB user

sudo -u postgres psql
CREATE DATABASE trello_clone_db;
DROP DATABASE 
# connect to DB
\c trello_clone_db;
\dt
# Create user for DB, grant all permission
CREATE USER db_dev WITH PASSWORD '123456';
GRANT ALL PRIVILEGES ON DATABASE trello_clone_db TO db_dev;
# DB adaptor for python

pip install psycopg2
pip install flask-sqlalchemy

# password_hash

pw_hash = bcrypt.generate_password_hash('hunter2')
bcrypt.check_password_hash(pw_hash, 'hunter2') # returns True