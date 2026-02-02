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
