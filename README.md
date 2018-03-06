# verify-okta

Small Lambda function for verifying and gating content with Okta

This allows users to use Okta's signin widget together with Netlify's JWT based visitor access control.

To us, compile with `GOOS=linux` and add the resulting binary to a lambda folder in your site as `lambda/verify-okta`

Setup access control to allow only logged in users with:

```
/* /:splat 200! Role=*
/* /login 200!
```

And then add a `netlify.toml` file similar to this:

```
[Build]
  Publish = "site"
  Functions = "lambda"

[template.environment]
  OKTA_BASE_URL = "base URL of your Okta account"
  OKTA_API_TOKEN = "An Okta API Token"
  OKTA_CLIENT_ID = "Client ID for your Okta app"
  JWT_SECRET = "JWT Secret set on team or site level"
```

Make sure your `login.html` include the script:

```
<script src="/.netlify/functions/verify-okta/okta.js"></script>
```

See https://github.com/netlify/example-gated-content-with-okta for a full example.

---

Note - this requires access to Netlify's AWS Lambda beta
