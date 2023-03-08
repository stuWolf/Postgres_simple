## PostgreSQL installation in Ubuntu (also valid for WSL)
## Iryna Shymbor
 — 
01/04/2023 9:52 AM
First of all, make sure the connection to the official postgres repositories is set.

sudo apt install wget ca-certificates


wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -


sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt/ $(lsb_release -cs)-pgdg main" >> /etc/apt/sources.list.d/pgdg.list'


sudo apt update


Everything should be updated now. Let's install postgres.

sudo apt install postgresql


Then, installation can be checked with commands. Check the installed version:

psql --version


To check database status:

service postgresql status


If the service is down, 

sudo service postgresql start

 will be needed.

Some PostgreSQL commands can be run from the terminal, but it is recommended to familiarise with PostgreSQL prompt. In Ubuntu, a postgres user is created by default, so first connection should be done with this user. Later, different users and roles can be created in the DBMS. Run this command to jump in it:

sudo -u postgres psql


To get more information about the database connection from the postgres prompt this command can be run. Notice that postgres runs on port 5432 by default.

\conninfo



---
If you hit an issue - please post in the questions channel 
Carol North
 — 
01/04/2023 11:52 AM
Hi Iryna. Wanting to do the pre-work yestrerday, I downloaded psql to windows before seeing this thread as I could not find the instructions anywhere on canvas/ed. (and I tried to do it in ubuntu first but kept getting errors ... are you root etc.. I eventually loaded it to windows successfully.... so... should I remove and try again through Ubuntu?
Iryna Shymbor
 — 
01/04/2023 11:54 AM
Hey Carol, yes please, and if you have any further issues/questions - please post them in the questions channel, we'll debug there 🙂
Carol North
 — 
01/04/2023 11:55 AM
will do 🙂 Happy New year btw ✨
Iryna Shymbor
 — 
01/04/2023 11:55 AM
Thanks, you too! 😊
Jake
 — 
01/07/2023 12:12 PM
To clarify here; doing sudo -u postgres psql is making the first connection with the user as you've mentioned?

Also in the video she says for windows we should have SQL shell (psql) now but the instructions imply we use psql off of ubuntu. Would you mind clarifying that for me please? (e.g. to use psql run 

sudo -u postgres psql

 every time?)

Thanks a bunch! 🙂
Iryna Shymbor
 — 
01/09/2023 9:10 AM
Hey Jake, the sudo -u postgres psql connects with postgres role. 
You can also create other roles and connect with those roles, using the same command but instead of postgres you'd need to use the role name you're connecting with.
Hope this helps 🙂 If you have any other questions, please ask in the questions channel
Jake
 — 
01/09/2023 9:40 AM
Thanks 🙂


## Postgres commands

# start postgres

sudo -u postgres psql

# create DB

CREATE DATABASE trello_clone_db;

# Connect to the database:

\c trello_clone_db;

# Create a user to manage this database:

CREATE USER db_dev WITH PASSWORD '123456';

GRANT ALL PRIVILEGES ON DATABASE trello_clone_db TO db_dev;

# commands

\l  list DB
\dt  list all tables
\d display table location
\q quit
select * from "cards";    show contents of table cards