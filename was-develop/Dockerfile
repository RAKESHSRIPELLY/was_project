FROM tiangolo/uwsgi-nginx-flask:python3.8

# Install a package, this removes the server details header
RUN apt-get update
RUN yes | apt-get -y install vim
RUN yes | apt-get install nginx-extras
RUN yes | apt-get install libgirepository1.0-dev
RUN yes | apt-get install libdbus-glib-1-dev libgirepository1.0-dev libcairo2-dev
RUN python3 --version
RUN apt-get update
RUN apt-get -y install default-jre
RUN java -version
RUN apt-get -y install default-jdk
RUN javac -version
#RUN java --version

# Configuration settings for UWSGI
ENV UWSGI_CHEAPER 4
ENV UWSGI_PROCESSES 64

# Which uWSGI .ini file should be used, to make it customizable
ENV UWSGI_INI /app/uwsgi.ini

## Copy app folder to app
COPY ./app /app

# Set app as the root directory
WORKDIR /app

# Make /app/* available to be imported by Python

ENV PYTHONPATH=/app

# Make permissions for mitm files
RUN chmod -R 777 /app/mitmdump
RUN chmod -R 777 /app/mitmweb
RUN chmod -R 777 /app/mitmproxy


# Copy dependencies to project root
COPY requirements.txt ./
#Copying Environment file
COPY was.env /was.env
COPY default_mongodb_update.py /default_mongodb_update.py
COPY was_env_update.py /was_env_update.py


# Install app dependencies
RUN pip3 install --no-cache-dir -r requirements.txt
RUN pip3 install cryptography
RUN pip3 install pywinrm
CMD ["python3" ,"execSuite.py"]
