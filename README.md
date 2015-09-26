# Guardian server for TOTP

Retrieves a token given a secret key.
Given a TOTP secret, the server validates Google Authenticator tokens

```
  curl http://localhost:9222/token/TOKEN
```

# Setup

Install the guardian

```
go get github.com/manuwell/guardian
```

See `.env.sample` to see what env vars you need to set

Run:

```
guardian
```

# Routes

```
  GET  /token/check/TOKEN

  # response
  {
    "Valid": true,
  }
```
