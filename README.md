# Minimal Authentication Prototype

# !! Please do not use this, it is a learning exercise prototype. Don't roll your own authentication. Use Azure AD B2C, AWS Cognito, Auth0, etc. !!

This prototype hosts a serverless (Azure Function) OpenID provider that integrates with Azure Easy Auth. 

* `AuthServer` is an Azure Function that authenticates the user and returns OIDC compliant data to the caller. Before deploying, generate private keys for JWT signing - see `AuthServer/cert/commands.sh`.
* `API` is an Azure Function that represents the API you want to secure with OpenID. Deploy it and enable Easy Auth in front of it - pointing it at `AuthServer`. Easy auth is half of the OIDC implemention, AuthServer is the other half.

To use it, GET `API`/SecureMePlease. Easy Auth is a proxy in front of that0; it checks if you have the necessary tokens. If not, redirects you to `AuthServer`/authorization to initiate OAuth flow. In theory, validate credentials here and then return true - but in this prototype, just return true. The OAuth handshake completes, cookies make it back to you, Easy Auth allows you to actually hit /SecureMePlease, which reflects some JWT variables back to you.

## How it works

* First, [understand easy auth](https://learn.microsoft.com/en-us/azure/app-service/overview-authentication-authorization), [more](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow )

* Attempt to access secured resource, API/SecureMePlease https://billy4560.azurewebsites.net/api/securemeplease
* Service is configured to use a custom OpenId provider with 
  * Issuer URL https://billyauthserver4560.azurewebsites.net
  * Authorization Endpoint https://billyauthserver4560.azurewebsites.net/authorization
  * Token Endpoint https://billyauthserver4560.azurewebsites.net/token
  * JWKS endpoint https://billyauthserver4560.azurewebsites.net/.well-known/jwks.json
* Easy Auth intercepts the request from to the protected resource and redirects to 
```
https://billyauthserver4560.azurewebsites.net/authorization?
  response_type=code
  &client_id=abcdclientidefgh
  &redirect_uri=https%3A%2F%2Fbilly4560.azurewebsites.net%2F.auth%2Flogin%2Fbilly%2Fcallback
  &nonce=14bced9620aa49519d3aab3ec7298007_20230124213205
  &state=redir%3D%252Fapi%252Fsecuremeplease
  &scope=openid+profile+email
```
* *This is meant to initiate authentication, verify username/password and such. But for the prototype I skip that part and just continue as if successfully authenticated.*
* Authorization endpoint (AuthServer/Authorization.cs/AuthorizationEndpoint()) 
  * Generates a code
  * Saves the code/nonce pair for later (it needs to end up in the JWT)
  * Redirects to redirect_uri?code=...&state=...
  * *"The authorization server MUST ignore unrecognized request parameters."*
  * (TODO) Validate callback URI is allow-listed 
* Redirect to
```
https://billy4560.azurewebsites.net/.auth/login/billy/callback?
  code=bg3DPvr6zezwR7gouT6fNfBqJWv_WGUCXDn0pjmyh8k
  &state=redir=%2Fapi%2Fsecuremeplease
```
* Token endpoint https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2
* Callback (Easy Auth Client) POSTs Token endpoint (actually POST body, not query string)
```
https://billyauthserver4560.azurewebsites.net/token?
  grant_type=authorization_code
  &code=bg3DPvr6zezwR7gouT6fNfBqJWv_WGUCXDn0pjmyh8k
  &redirect_uri=https%3A%2F%2Fbilly4560.azurewebsites.net%2F.auth%2Flogin%2Fbilly%2Fcallback
  &client_id=abcdclientidefgh
  &client_secret=1234secret5678
```
* And does:
  * (TODO) Token endpoint needs to verify that code matches that issued by Authorization endpoint
  * (TODO) Validate Redirect URI matches from Authorization step
  * (TODO) Validate client ID & secret match previously-exchanged data
  * Generate an Access Token (JSON) with JWT 
```
{
   "access_token":"EwaAbJtPd1VpRkrX-2gPV2ctRaE",
   "token_type":"Bearer",
   "expires_in":3600,
   "scope":"openid profile email",
   "id_token":"redacted_jwt"
}
```
* JWT (id_token) from above parses as:
```
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "IGKDhS52CyJUTRSNQdVuONUSaop1tUczTElm0kP83Zg"
}
.
{
  "nickname": "usernamehere",
  "name": "usernamehere@example.com",
  "picture": "https://s.gravatar.com/avatar/foo",
  "updated_at": "2023-01-21T18:27:11.339Z",
  "email": "usernamehere@example.com",
  "email_verified": "true",
  "iss": "https://billyauthserver4560.azurewebsites.net",
  "sub": "0fdc763c-e830-4db2-a5c7-f2e59a27e6ac",
  "aud": "abcdclientidefgh",
  "iat": 1674595626,
  "exp": 1674599226,
  "nonce": "14bced9620aa49519d3aab3ec7298007_20230124213205"
}
.
```
* Client validates above was signed with public key at 
  * JWKS URL https://billyauthserver4560.azurewebsites.net/.well-known/jwks.json
```
{
  "keys": [
    {
      "e": "AQAB",
      "kid": "IGKDhS52CyJUTRSNQdVuONUSaop1tUczTElm0kP83Zg",
      "kty": "RSA",
      "n": "z5XQZ0YYFNbecQSETuVGlXZtS7gpY9u6SKcmtGqU4BGPjEA38DliKW76xVMrOvOooO_3MDxHluIXUsX7PHyyJQQ71U6tg1nEavcu3GGDJMHVgEsVEMa8dNg90v4HLeLqB7pCHvNMBQk2kURdt690_ED52w7J3F1lLAMOyL1QZLpQAuYSP7N277m5lwquuF9AI0M8iqRnrY5PYaREt66Mi8sVojBm7iLKpzQKHOU67bL427etCgH8wG2Z-1w-5mDuaBaDstdKxElfawyv3fKVVBQXK9Hu4C2dbmR8SoLjJOSdeQGeuOfrybllrqFV0HzwvUA68jZ8fjU5Zzj5T73v-w"
    }
  ]
}
```
* In addition to crypto validation, client validates issuer, audience, iat, exp, and nonce.
* Client then redirects browser to https://billy4560.azurewebsites.net/api/securemeplease with a new magical `AppServiceAuthSession` cookie that is a black box to me. Easy Auth knows how to validate it and allows the request to go through. 

```
var claims = new Dictionary<string, string>();
foreach (var c in identity.Claims)
{
    claims.Add(c.Type, c.Value);
}
```
returns
```
{
  "nickname":"usernamehere",
  "name":"usernamehere@example.com",
  "picture":"https://s.gravatar.com/avatar/foo",
  "updated_at":"2023-01-21T18:27:11.3390000Z",
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":"usernamehere@example.com",
  "email_verified":"true",
  "iss":"https://billyauthserver4560.azurewebsites.net",
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier":"0fdc763c-e830-4db2-a5c7-f2e59a27e6ac",
  "aud":"abcdclientidefgh",
  "iat":"1674595626",
  "exp":"1674599226",
  "nonce":"14bced9620aa49519d3aab3ec7298007_20230124213205"}
```
For https://learn.microsoft.com/en-us/dotnet/api/system.security.claims.claimtypes.email?view=net-7.0

## Lessons learned
### "Pretty brittle, eh?"

* It's not really that hard! The concepts are approachable, but the details are nuanced. Aside from fiddly little details, there's the whole crypto thing! It's only like 250 lines of code because libraries are so thorough. 
* Read the spec carefully! I missed details about claims required in openid and how the client validates. Namely, issuer, audience, iat, exp, and nonce. 
* I chased a red herring about RSA keys that I don't think mattered - but I like the solution I have for generating keys now. 
* JWT verifiers
  * https://jwt.io/ - OG
  * https://jwt.davetonge.co.uk/ - validates JWKS too
  * https://jwt.ms/ - has nice snippets from RFC to help understand 
  * https://www.jstoolset.com/jwt - nice formatting

## Commands

```
func azure functionapp publish Billy4560
```
