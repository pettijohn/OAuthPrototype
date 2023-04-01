using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Newtonsoft.Json;

namespace OAuthSpike
{
    public record Client(string clientID, string clientSecret);

    public record AccessToken(string access_token, string token_type, int expires_in, string scope, string id_token);

    public static class Authorization
    {
        public static Client Client = new Client("abcdclientidefgh", "1234secret5678");
        private static string _email = null;
        private static string _otp = null;
        private static Dictionary<string, string> _codeNonceCache = new Dictionary<string, string>();


        [FunctionName("authorization")]
        public static async Task<IActionResult> AuthorizationEndpoint(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = null)] HttpRequest req,
            ILogger log)
        {
            /*
            https://billyauthserver4560.azurewebsites.net/authorization?
                response_type=code
                &client_id=abcdclientidefgh
                &redirect_uri=https%3A%2F%2Fbilly4560.azurewebsites.net%2F.auth%2Flogin%2FBilly%2Fcallback
                &nonce=52f1b2f0fb4443ea94f5bfef84e4ef77_20230123174909&state=redir%3D%252Fapi%252Fsecuremeplease
                &scope=openid+profile+email
            */

            log.LogWarning(req.QueryString.Value);
            var body = await new StreamReader(req.Body).ReadToEndAsync();
            log.LogWarning(body);

            // Cache the code/nonce pair
            var code = CertUtil.GenerateCryptographicallyStrongString();
            _codeNonceCache.Add(code, req.Query["nonce"]);
            // Validate client ID - look up in spec: 'Location: ' . $baseURL . '?error=invalid_state'
            if(String.IsNullOrEmpty(req.Query["client_id"]) || req.Query["client_id"] != Client.clientID) return new NotFoundResult();

            var uri = $"{req.Query["redirect_uri"]}?code={code}&state={req.Query["state"]}";
            log.LogWarning($"Redirecting to {uri}");
            return new RedirectResult(uri, false) ;
        }

        [FunctionName("token")]
        public static async Task<IActionResult> TokenEndpoint(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req,
            ILogger log,
            ExecutionContext context)
        {
            /*
            https://billyauthserver4560.azurewebsites.net/token?
                grant_type=authorization_code
                &code=uWhKQ%2FDcz0DVbkFQExtnJzbsaz0%3D
                &redirect_uri=https%3A%2F%2Fbilly4560.azurewebsites.net%2F.auth%2Flogin%2FBilly%2Fcallback
                &client_id=abcdclientidefgh
                &client_secret=1234secret5678
            */

            log.LogWarning(req.QueryString.Value);
            var body = await new StreamReader(req.Body).ReadToEndAsync();
            log.LogWarning(body);

            var keyValues = System.Web.HttpUtility.ParseQueryString(body);
            var code = keyValues["code"];
            
            // Verify code matches code issued by Authentication step and that it is only used once to prevent replay attacks 
            if(!_codeNonceCache.ContainsKey(code)) return new NotFoundResult();
            var nonce = _codeNonceCache[code];
            _codeNonceCache.Remove(code);
            //if(string.IsNullOrEmpty(code)) code = "Error getting code from body " + Guid.NewGuid().ToString();

            return new JsonResult(new AccessToken(CertUtil.GenerateCryptographicallyStrongString(),
            "Bearer", 3600, "openid profile email", GetJwt(nonce, log, context)));
        }



        // https://stackoverflow.com/questions/69117288/sign-jwt-token-using-azure-key-vault
        // See cert/commands.sh to generate keys
        public static string GetJwt(string nonce, ILogger log, ExecutionContext context)
        {
            log.LogWarning("GetJwt()");


            var now = DateTimeOffset.UtcNow;
            var expiryTime = now.AddMinutes(60).ToUnixTimeSeconds();

            // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.7 - required claims / client verification 
            // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.1 - addn standard claims 
            var claims = new[]
            {
                new Claim("nickname", "usernamehere"),
                new Claim(JwtRegisteredClaimNames.Name, "usernamehere@example.com"),
                new Claim("picture", "https://s.gravatar.com/avatar/foo"),
                new Claim("updated_at", "2023-01-21T18:27:11.339Z"),
                new Claim(JwtRegisteredClaimNames.Email, "usernamehere@example.com"),
                new Claim("email_verified", "true"),
                
                // The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the iss (issuer) Claim.
                // REQUIRED. Issuer Identifier for the Issuer of the response. The iss value is a case sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components. 
                new Claim(JwtRegisteredClaimNames.Iss, "https://billyauthserver4560.azurewebsites.net"),
                
                // REQUIRED. Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII characters in length. The sub value is a case sensitive string. 
                new Claim(JwtRegisteredClaimNames.Sub, "0fdc763c-e830-4db2-a5c7-f2e59a27e6ac"),

                // REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value. It MAY also contain identifiers for other audiences. In the general case, the aud value is an array of case sensitive strings. In the common special case when there is one audience, the aud value MAY be a single case sensitive string.
                // The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified by the iss (issuer) Claim as an audience.
                new Claim(JwtRegisteredClaimNames.Aud, Client.clientID),
                
                // https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/838#issuecomment-509304278
                // This doesn't seem to matter for Easy Auth, but quotes breaks the decoder at https://jwt.io
                new Claim(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.Exp, expiryTime.ToString(), ClaimValueTypes.Integer64),

                //new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Add JTI for additional security against replay attacks
                new Claim(JwtRegisteredClaimNames.Nonce, nonce), // From the initial request

            };

            log.LogWarning("Reading private key");
            var certPath = Path.Combine(context.FunctionAppDirectory, "cert", "privkey-rsa-2048.pkcs8.pem");
            var rsaSecurityKey = CertUtil.GetPrivateKey(certPath);

            log.LogWarning("Creating token");
            var jwt = CertUtil.CreateJwt(rsaSecurityKey, claims);
            log.LogWarning($"Returning token {jwt}");
            return jwt;
        }

        [FunctionName("jwks")]
        public static async Task<IActionResult> PublicKey(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = ".well-known/jwks.json")] HttpRequest req,
            ILogger log,
            ExecutionContext context)
        {

            log.LogWarning("Reading private key");
            var certPath = Path.Combine(context.FunctionAppDirectory, "cert", "privkey-rsa-2048.pkcs8.pem");
            var rsaSecurityKey = CertUtil.GetPrivateKey(certPath);

            var result = CertUtil.GetJwks(new[] {rsaSecurityKey.Rsa.ExportParameters(false)});

            return new ContentResult() { Content = result, ContentType = "application/json", StatusCode = 200 };
        }
    }
}
