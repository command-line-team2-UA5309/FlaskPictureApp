# FlaskPictureApp

## How to set up pre-commit hooks

1. Install pre-commit from <https://pre-commit.com/#install>
2. Run `pre-commit install`
3. Auto-update the config to the latest version `pre-commit autoupdate`

## Load environment variables from .env before running app on server

```bash
set -o allexport
source .env set
set +o allexport
```

## Setup for local testing

### Create virtual environment and install dependencies

```bash
python3 -m venv .venv

. .venv/bin/activate

pip install -r requirements.txt
```

### Setup database

* Create db

```bash
sudo -iu postgres psql

postgres=# CREATE DATABASE db_name;

postgres=# CREATE USER username PASSWORD 'password';

postgres=# GRANT ALL PRIVILEGES ON DATABASE db_name TO username;

postgres=# ALTER DATABASE db_name OWNER TO user;
```

* Run script for setup tables in db

```
python3 init_tables.py 
```

### Setup S3 compatible storage

* Install SeaweedFS

```
cd /tmp

# If arm install this one
wget https://github.com/seaweedfs/seaweedfs/releases/download/4.09/linux_arm64.tar.gz

# If x86 install this one
wget https://github.com/seaweedfs/seaweedfs/releases/download/4.12/linux_amd64.tar.gz

sudo mv weed /usr/local/bin/weed
```

* Starting server

```
sudo weed mini -dir=/images -s3 -ip.bind 0.0.0.0 -ip your_mashine_ip
```

* Info about setting up bucket you can find [here](https://hub.relution.io/en/docs/installation/object-storage/seaweedfs/) on step 3

### Run application

```
python3 app.py
```
