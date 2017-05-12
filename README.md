# lambda-authentication

Openid connect for API Gateway custom authorizers & Serverless

## requirements

This package is intended to run on node v6.10.x (the latest version of node available to lambda at the time)

## usage

First, export the authorizer with the correct path:

```js
const authorizer = require('@life-without-barriers/lambda-authentication').authorizer

exports.myAuthorizer = authorizer({
  path: '/my-cool-site', // The path to your API
  logger: bunyan.createLogger({ name: 'my-app' }), // Accepts any bunyan logger. optional
  audience: 'abc123', // The openid connect client id
  discoveryUrl: 'https://my-openid-server/.well-known/openid-configuration', // the openid connect discovery URL
  issuer: 'my-openid-org', // the openid connect issuer
  cookieName: 'foo' // the name of the cookie that contains the JWT
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
