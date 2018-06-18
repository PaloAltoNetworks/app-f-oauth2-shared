# Application Framework OAUTH2 Shared Component
This serverless application is an example implementation of a OAUTH2 Shared Component to interface with the Palo Alto Networks Application Framework authentication service.

# Instructions
The application is named [oauth2shared](https://serverlessrepo.aws.amazon.com/#/applications/arn:aws:serverlessrepo:us-east-1:760265413520:applications~oauth2shared) and is publicly available from the AWS Serverless Repository. Just deploy it into your AWS Account.

The deployment will trigger a CloudFormation stack that will create the following components into your AWS Account:
* API Gateway named **Oauth2SharedGateway**
* Lamba Function named **Oauth2SharedLamdba**
* IAM Role named **aws-serverless-repository-o-Oauth2SharedLamdbaRole...**

Both the _API Gateway_ and the _IAM Role_ will need some adjustment before the application can be used.
## IAM Role inline policies for AWS Secrets Manageer
This serverless application will store application credentials (*access_token*, *refresh_token*) in the **AWS Secrets Manager** service. The deployment will create an IAM Role named _aws-serverless-repository-o-Oauth2SharedLamdbaRole..._ with the RO AWS Managed Policy named *AWSLambdaBasicExecutionRole* attached to it. You must add an inline policy to the role to allow the lamdba function be able to interface with the _Secrets Manager_
1. Navigate in the AWS Console to Services -> IAM -> Roles
2. Click on the role named _aws-serverless-repository-o-Oauth2SharedLamdbaRole..._
3. Click on **Add inline policy** and select the following options:
  - Service = **Secrets Manager**
  - Access Level Read = all (_Describe Secret_, _GetSecretValue_)
  - Access Level Write = _CreateSecret_, _PutSecretValue_ and _DeleteSecret_
  - Resources = all
4. Review the new polciy, give it a name and create the new policy.
> **Alert**
> This inline policy will prevent the CloudFormation template from deleting the stack. If you want to use the CloudFormation to revert the application deployment then remember to remove this inline policy from the IAM Role first.

## API Gateway Stage Variables and the Application Portal **manifest file**
Deployment of applications in the Application Framework application portal is currently a manual procedure. The partner must submit a _manifest file_ describing his application to the Palo Alto Networks DevOps team. A sucessfull deployment of the application into the portal will provide back the partner with a _master secret document_ containing two critical attributes needed for the OAUTH2 process: the **client_id** and the **client_secret**.

The lambda function relies on some variables whose values are provided as _stage variables_ in the API Gateway. The CloudFormation template will ceate a stage named **AppF** and pre-populate the needed _stage variables_.
1. Navigate in the AWS Console to Services -> API Gateway -> APIs -> _Oauth2SharedGateway_
2. Click on the Stage named _AppF_
3. Click on the tab _Stage Variables_
  - `applicationName` must match the value of the parameter `name` in the manifest file.
  - `applicationScope` must be a string separated sequence of the entries in the parameter `scopes` in the manifest file (example: "logging-service:read event-service:read directory-sync-service:read").
  - `applicationCallbackUrl` this value must match the value of the parameter `auth_redirect_uris` in the manifest file. The URL must resolve to the lambda function. This means that it must be any child path of the API Gateway invocation URL (or mapped custom domain). If you use the automatically created invocation url then remember that the _stage_ path will be removed during the integration process. For example, if your invocation URL happens to be https://cmpxxx65.execute-api.eu-west-1.amazonaws.com/AppF then a valid value for `applicationCallbackUrl` could be https://cmpxxx65.execute-api.eu-west-1.amazonaws.com/callback (notice _AppF_ is missing).
  - Replace the value of the variable `applicationWelcomePage` with the URL of a Welcome Page for the user. The user's browser will be redirected to this URL at the end of the authentication process (or when clicking on your activated application tile in the portal). You can explore this [example page](https://s3-eu-west-1.amazonaws.com/oauth2shared/welcome.html)
  - For each successfull application activation the lambda function will generate and provide back an **API_KEY** to be shared with the application software deployement. Internally, a secret index will be created using the function `sha256hmac(API_KEY, shared_secret)` the value of the variable `applicationSharedSecret` must contain this *shared_secret* to be known only to the lamda function and all application software deployments.

## Secrets Manager **Master Secret**
The lambda function needs access to the master *client_id* and *client_secret* to perform authentication operations. It will try to get these values from the _AWS Secrets Manager_ service looking for a secret named *<applicationName>_master* (being _applicationName_ the name you provided in the manifest file).

Use the *AWS Secrets Manager* console to create the master secret.
1. Navigate in the AWS Console to Services -> Secrets Manager
2. Click on _Store a new secret_.
3. Select _Othe type of secrets_ and go to the next page.
4. Use key_value type of storage to create the secrets content with the following two entries:
  - `client_id` with a value equal to the *client_id* value provided back by Palo Alto Networks DevOps after a successful application deployment into the portal.
  - `client_secret` with a value equal to the *client_secret* value provided back by DevOps.

5. The _Secret name_ must conform to *<applicationName>_master* schema.
6. Keep disabled _automatic rotation_ and store the secret.

## Token operations
The serverless application implements the `/token` entry point to deal with token operations. A unique query string parameter named `api_secret` must be provided. Its value can be calculated as `sha265hmac(API_KEY, shared_secret)`. You can use [online hmac calculator](https://www.freeformatter.com/hmac-generator.html) for manual testing of the API.
* GET: Will provide back with a JSON document including the last known *access_token* and its *expiration* time (UTC timestamp).
* PUT: Will trigger a token refresh operation and return the new *access_token* value and expiration timestamp.
* DELETE: To delete the corresponding secret in the AWS Secrets Manager service. The AWS administrator can revert this operation from the AWS Secrets Manager console for 30 days.