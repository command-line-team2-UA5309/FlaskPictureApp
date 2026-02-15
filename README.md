# FlaskPictureApp

## How to set up pre-commit hooks

1. Install pre-commit from <https://pre-commit.com/#install>
2. Run `pre-commit install`
3. Auto-update the config to the latest version `pre-commit autoupdate`

## Setup for local testing

### Create virtual environment and install dependencies

```bash
python3 -m venv .venv

. .venv/bin/activate

pip install -r requirements.txt
```

### Create .env file

Create .env file in the root directory with all the secrets:

```bash
DB_NAME=""
DB_PASSWORD=""
DB_USER=""
DB_HOST=""
DB_PORT=""

SECRET_KEY=""

ENDPOINT=""
S3_ACCESS_KEY=""
S3_SECRET_KEY=""
BUCKET_NAME=""
```

### Load environment variables from .env before running app on server

```bash
set -o allexport
source .env set
set +o allexport
```

### Setup database

Run `flask db upgrade`

### Setup S3 compatible storage

* Install SeaweedFS

```bash
cd /tmp

# If arm install this one
wget https://github.com/seaweedfs/seaweedfs/releases/download/4.09/linux_arm64.tar.gz

# If x86 install this one
wget https://github.com/seaweedfs/seaweedfs/releases/download/4.12/linux_amd64.tar.gz

sudo mv weed /usr/local/bin/weed
```

* Starting server

```bash
sudo weed mini -dir=/data -s3 -ip.bind 0.0.0.0 -ip your_mashine_ip
```

* Info about setting up bucket you can find here:
[SeaweedFS config credentials](https://hub.relution.io/en/docs/installation/object-storage/seaweedfs/)
on step 3

### Run application

```bash
python3 app.py
```

## How to create new migration

Run `flask db migrate -m "<Migration name>"`

> [!WARNING]
> It is necessary to create new migration every time new changes to the 
> database structure are implemented.
