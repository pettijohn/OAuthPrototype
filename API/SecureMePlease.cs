using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;

namespace OAuthSpike
{
    public static class SecureMePlease
    {
        [FunctionName("SecureMePlease")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            // var user = req.HttpContext.User;
            // user.
            // string name = req.Query["name"];
            
            var identity = req.GetAppServiceIdentity();

            var claims = new Dictionary<string, string>();
            foreach (var c in identity.Claims)
            {
                claims.Add(c.Type, c.Value);
            }

            // https://learn.microsoft.com/en-us/dotnet/api/system.security.claims.claimtypes.email?view=net-7.0
            //var email = identity.Claims.First(c => c.Type == ClaimTypes.Email);

            /*
            {
                "nickname": "usernamehere",
                "name": "usernamehere@example.com",
                "picture": "https://s.gravatar.com/avatar/foo",
                "updated_at": "2023-01-21T18:27:11.3390000Z",
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "usernamehere@example.com",
                "email_verified": "true",
                "iss": "https://billyauthserver4560.azurewebsites.net",
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "abcdclientidefgh",
                "aud": "abcdclientidefgh",
                "iat": "1674590923",
                "exp": "1674594523",
                "jti": "20955b26-2d0b-4a99-87fc-01f219060aab",
                "nonce": "108abcee3a9b4da4a2876dd6a500201d_20230124201342"
            }
            */

            return new JsonResult(claims);
        }
    }
}
