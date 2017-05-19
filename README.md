# lambda-authentication

[![volkswagen status](https://auchenberg.github.io/volkswagen/volkswargen_ci.svg?v=1)](https://github.com/auchenberg/volkswagen)

JWT auth for API Gateway custom authorizers & Serverless

Uses HMACSHA256 with a shared secret. If you are using tokens signed using RSA, v1 might give you some ideas.
Uses a cookie to roundtrip the JWT, so make sure you consider CSRF protection on your api endpoints.

## requirements

This package is intended to run on node v6.10.x (the latest version of node available to lambda at the time)

## usage

First, export the authorizer with the correct path:

```js
const authorizer = require('@life-without-barriers/lambda-authentication').authorizer

exports.myAuthorizer = authorizer({
  path: '/my-cool-site', // The path to your API
  logger: bunyan.createLogger({ name: 'my-app' }), // Accepts any bunyan logger. optional
  audience: 'abc123', // The audience
  issuer: 'my-openid-org', // the issuer
  cookieName: 'foo', // the name of the cookie that contains the JWT
  secret: 'secret key for HMAC signing'
})
```

Then, expose the lambda in your `serverless.yml` and delegate authorization to it:

```yml
functions:
  myAuthorizer:
    handler: app.myAuthorizer
  app:
    handler: app.myApp
    events:
      - http:
          path: /my-cool-site
          method: get
          cors: true
          authorizer:
            name: myAuthorizer
            identitySource: method.request.header.Cookie # IMPORTANT! use cookie auth
```
