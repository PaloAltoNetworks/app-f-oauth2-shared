# Application Framework OAUTH2 Shared Component
This serverless application is an example implementation of a OAUTH2 Shared Component to interface with the Palo Alto Networks Application Framework authentication service.
The following API Gateway environment variables must be configured for the application to perform its function:
* `applicationWelcomePage`: The user browser will be redirected to this page. You can explore this [example page](https://s3-eu-west-1.amazonaws.com/oauth2shared/welcome.html)
* `applicationCallbackUrl`: The hostname must resolve to this application (look for documentation on Custom Domain Names for AWS API GW) and the path something like `/callback`. This value must match the value of the parameter `auth_redirect_uris` in the manifest file.
* `applicationName`: The name of the application in the Application Framework Portal. Must match the value of the parameter `name` in the manifest file.
* `applicationSharedSecret`: TODO
* `applicationScope`: Resources the application must have access to. Must be a string separated sequence of the entries in the parameter `scopes` in the manifest file.