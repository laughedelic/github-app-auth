# GitHub App auth for Deno

A minimal Deno library and a CLI app to authenticate as a GitHub App
installation.

## Usage

### CLI

#### Installation

```shell
deno install --allow-net=api.github.com https://deno.land/x/github_app_auth/cli.ts
```

Then you can use it as `github_app_auth ...`.

#### Expected inputs

- `app-id`: you can find it in the application settings
- `private-key`: Base64-encoded content of the private key `.pem` file you got
  when you created the app, converted into pkcs8 format
- `installation-id`: organization or user installation ID you want to get access
  to
- `repositories` (optional, trail-arg): list of repositories to give access to;
  if not provided, it will be all repositories that the installation can access

See the
[API endpoint documentation](https://docs.github.com/en/rest/reference/apps#create-an-installation-access-token-for-an-app)
for more info.

#### Converting the GitHub Private Key

The private key that github generates is a `pkcs1` format key but Deno only
supports `pkcs8`. To convert it you can use openssl:

```sh
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in ~/Downloads/example.2024-11-12.private-key.pem -out private-key.key
```

#### GitHub API URL

If you need to change the default GitHub API URL, you can do it by setting the
`GITHUB_API_URL` env var and adding `--allow-env=GITHUB_API_URL` when you
install the script:

```shell
export GITHUB_API_URL='...'
deno install --allow-net="$GITHUB_API_URL" --allow-env='GITHUB_API_URL' https://deno.land/x/github_app_auth/cli.ts
```

Or use `--allow-net --allow-env` for simplicity.

#### Examples

Given app ID, private key and then installation ID it will create a new
installation access token and print it to the standard output:

```shell
$ github_app_auth 123456 $(base64 < private-key.pem) 12345678
ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

If you don't know the installation ID, you can run it with only the first two
arguments and get a list of the app installations:

```shell
$ github_app_auth 123456 $(base64 < private-key.pem)
[
  {
    "id": 12345678,
    ...
```

You can use generated tokens to make requests on behalf on the app. Here are
some examples using GitHub's official CLI `gh`, but you can also do it with
`curl` or any other tool by adding the `Authorization: token ...` header.

```shell
$ GITHUB_TOKEN=$(github_app_auth 123456 $(base64 < private-key.pem) 12345678)

$ gh auth status
github.com
  ✓ Logged in to github.com as your-app-name[bot] (GITHUB_TOKEN)
  ✓ Git operations for github.com configured to use https protocol.
  ✓ Token: *******************

$ gh api installation/repositories --jq '.repositories[].name'
repo1
repo2
...

$ gh api repos/:owner/repo1/releases
...
```

Check out [`gh api` docs](https://cli.github.com/manual/gh_api) for more
examples and full feature list.
