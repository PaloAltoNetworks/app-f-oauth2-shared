# Application Framework OAUTH2 Shared Component
This serverless application is an example implementation of a OAUTH2 Shared Component to interface with the Palo Alto Networks Application Framework authentication service.

# Installation
The application is named [oauth2shared](https://serverlessrepo.aws.amazon.com/#/applications/arn:aws:serverlessrepo:us-east-1:760265413520:applications~oauth2shared) and is publicly available from the AWS Serverless Repository. Just deploy it into your AWS Account.

The deployment will trigger a CloudFormation stack that will create the following components into your AWS Account:
* API Gateway named **oauth2sharedgw**
* Lamba Function named **oa2scmp**
* IAM Role named **newoa2cft-oauth2sharedlambdaRole-...**

The _IAM Role_ will need some adjustment before the application can be used.
## IAM Role inline policies for AWS Secrets Manager
This serverless application will store application credentials (*access_token*, *refresh_token*) in the **AWS Secrets Manager** service. The deployment will create an IAM Role named _newoa2cft-oauth2sharedlambdaRole-..._ with the RO AWS Managed Policy named *AWSLambdaBasicExecutionRole* as well as a Inline Policy rule named *oauth2sharedlambdaRolePolicy0* attached to it. You must add/edit an/the inline policy to the role to allow the lamdba function be able to interface with the _Secrets Manager_
1. Navigate in the AWS Console to Services -> IAM -> Roles
2. Click on the role named _aws-serverless-repository-o-Oauth2SharedLamdbaRole..._
3. Click on **Add inline policy** and select the following options:
  - Service = **Secrets Manager**
  - Access Level Read = **GetSecretValue**
  - Access Level Write = **CreateSecret**, **PutSecretValue** and **DeleteSecret**
  - Resources = **all**
4. Review the new polciy, give it a name and create the new policy.
> **Alert**
> This inline policy will prevent the CloudFormation template from deleting the stack. If you want to use the CloudFormation to revert the application deployment then remember to remove this inline policy from the IAM Role first.

## API Gateway Application Portal **manifest file**
Deployment of applications in the Application Framework application portal is currently a manual procedure. The partner must submit a _manifest file_ describing his application to the Palo Alto Networks DevOps team. A sucessfull deployment of the application into the portal will provide back the partner with a _master secret document_ containing two critical attributes needed for the OAUTH2 process: the **client_id** and the **client_secret**.

The lambda function behavior can be tuned with some variables whose values are provided as _stage variables_ in the API Gateway. The CloudFormation template will ceate a stage named **prod** and pre-populate the only mandatory _stage variables_.
1. Navigate in the AWS Console to Services -> API Gateway -> APIs -> _oauth2sharedgw_
2. Click on the Stage named _prod_
3. Click on the tab _Stage Variables_
  - `DBTABLE` (mandatory) The CFT must have created a Dynamod DB table with this name as well as to provide CRUD access level to that table to the lambda function (inline policy in the IAM's role named _newoa2cft-oauth2sharedlambdaRole-..._).
  - `SCOPE` (optional / defaults to "") must be a string separated sequence of a subset of the entries in the parameter `scopes` in the manifest file (example: "logging-service:read event-service:read").
  - `MASTERSECRET` (optional) It will be used to HMAC the user passwords in the database. Do not change/provide this stage variable once the first user account has been created.
  - `SMPREFIX` (optionals / defaults to 'oa2s') A prefix that will be used for all generated secrets stored in AWS' Secrets Manager service
  - `AUTOREFRESH` (optional / defaults to 'false') Triggers the _autoRefresh_ feature in the token manager entry point. If set to true, then any _GET:/token_ operation performed in the last 5 minutes of the access token validity will trigger a _GET:/token/refresh_ operation and return the refresed access token.
  - `SESSTOUT` (optional / defaults to 30 minutes) Application idle user session timeout.
  - `SESSGUARD` (optional / defaults to 5 minuts) Guard period before session's timeout point that will trigger a new session cookie.
  - `COOKIENAME` (optional / defaults to 'oauth2shared') Cookie name that will be used to keep session access token.

## Secrets Manager **Master Secret**
The lambda function needs access to the master *client_id* and *client_secret* to perform authentication operations. It will try to get these values from the _AWS Secrets Manager_ service looking for a secret named *[SMPREFIX]_master* (being SMPREFIX the value you provided / defaulted-to in AWS API Gateway Stage Variable).

Use the *AWS Secrets Manager* console to create the master secret.
1. Navigate in the AWS Console to Services -> Secrets Manager
2. Click on _Store a new secret_.
3. Select _Other type of secrets_ and go to the next page.
4. Use key_value type of storage to create the secrets content with the following two entries:
  - `client_id` with a value equal to the *client_id* value provided back by Palo Alto Networks DevOps after a successful application deployment into the portal.
  - `client_secret` with a value equal to the *client_secret* value provided back by DevOps.

5. The _Secret name_ must conform to *[SMPREFIX]_master* naming layout.
6. Keep disabled _automatic rotation_ and store the secret.

# Manifest File
Although you can use the application as-is, it is highly recommended to create a _Custom Domain Name_ entry for your application.
1. Navigate in the AWS Console to Services -> API Gateway
2. Select Custom Domain Names and click on the _Create Custom Domain Name_ button
3. Provide a _Domain Name_ and the _ACM Certificate_ you want to bound that custom name to. If you do not have any ACM Certificate yet then create one in the _AWS Certificate Manager_ service before completing this step.
4. Click on _Edit_ to create a new _Base Path Mapping_
  - Path should be '/'
  - Destination should be 'oauth2sharedgw:prod'
5. It will take some minutes for the Certificate Manager service to bound the new Custom Domain Name to the certificate. During that time create a new CNAME in your hosted DNS Domain to point the application _Invoke URL_ (you can get that url from API GW -> oauth2sharedgw -> Stages -> Prod)

Provide the following values in the corresponding Application Framework Manifest File:
- app_base_url: https://{FQDN} (being {FQDN} the CNAME record you created in the step 5)
- auth_redirect_uris: This value is a field. Provide, at least the entry https://{FQDN}/callback
- scopes: Also a list. Provide at least one entry for each item you provided in the spaced-separated _SCOPE_'s API GW Stage Variable value

# Instructions
Check the [GitHub Wiki space](https://github.com/PaloAltoNetworks/app-f-oauth2-shared/wiki) for details.