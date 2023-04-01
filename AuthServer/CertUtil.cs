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
using System.Text.RegularExpressions;

namespace OAuthSpike
{
    public static class CertUtil
    {

        /// <summary>
		/// Returns a new random string.
		/// </summary>
		/// <returns>The new random string.</returns>
		public static string GenerateCryptographicallyStrongString() {
            var buffer = RandomNumberGenerator.GetBytes(32); //256 bits of entropy
            return Base64UrlEncoder.Encode(buffer);
            // See also Base58 encoder https://gist.github.com/micli/c242edd2a81a8f0d9f7953842bcc24f1
		}

        /// <summary>
        /// Read a PEM-encoded RSA private key, strip the --BEGIN/END markers, load into a
        /// </summary>
        public static RsaSecurityKey GetPrivateKey(string certPath)
        {
            var privateKey = File.ReadAllText(certPath)
                .Replace("-----BEGIN PRIVATE KEY-----", "")
                .Replace("-----END PRIVATE KEY-----", "");

            //log.LogWarning("Convert to Bytes");
            var privateKeyRaw = Convert.FromBase64String(privateKey);

            //log.LogWarning("Import RSA");
            var provider = new RSACryptoServiceProvider(); // This is IDisposable
            provider.ImportPkcs8PrivateKey(new ReadOnlySpan<byte>(privateKeyRaw), out _);
            var rsaSecurityKey = new RsaSecurityKey(provider);
            return rsaSecurityKey;
        }

        /// <summary>
        /// Compute a Base64UrlEncoded SHA256 hash of e, kty, and n to create a unique ID for KID
        /// </summary>
        public static string ComputeKeyID(RSAParameters parameters)
        {
            var e = Base64UrlEncoder.Encode(parameters.Exponent);
            var n = Base64UrlEncoder.Encode(parameters.Modulus);
            var dict = new Dictionary<string, string>() {
                {"e", e},
                {"kty", "RSA"},
                {"n", n}
            };
            var hash = SHA256.Create();
            Byte[] hashBytes = hash.ComputeHash(System.Text.Encoding.ASCII.GetBytes(JsonExtensions.SerializeToJson(dict)));
            var kid = Base64UrlEncoder.Encode(hashBytes);
            return kid;
        }
        /// <summary>
        /// Compute a Base64UrlEncoded SHA256 hash of e, kty, and n to create a unique ID for KID
        /// </summary>
        public static string ComputeKeyID(RsaSecurityKey rsaSecurityKey)
        {
            return ComputeKeyID( rsaSecurityKey.Rsa.ExportParameters(false));
        }

        /// <summary>
        /// Use the provided security key to sign the claims into a JWT
        /// </summary>
        public static string CreateJwt(RsaSecurityKey rsaSecurityKey, IEnumerable<Claim> claims)
        {
            var handler = new JwtSecurityTokenHandler();
            var token = new JwtSecurityToken
            (
                new JwtHeader(new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256)),
                new JwtPayload(claims)
            );
            token.Header.Add("kid", ComputeKeyID(rsaSecurityKey));

            var jwt = handler.WriteToken(token);
            return jwt;
        }

        public static string GetJwks(IEnumerable<RSAParameters> keys)
        {
            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet();
            foreach (var key in keys)
            {
                var e = Base64UrlEncoder.Encode(key.Exponent);
                var n = Base64UrlEncoder.Encode(key.Modulus);
                JsonWebKey jsonWebKey = new JsonWebKey()
                {
                    Kty = "RSA",
                    Kid = ComputeKeyID(key),
                    E = e,
                    N = n,
                    // Alg = "RS256",
                    // Use = "sig"
                    // X5t = "",
                    // X5c = ""
                };
                jsonWebKeySet.Keys.Add(jsonWebKey);
            }
            var result = JsonExtensions.SerializeToJson(jsonWebKeySet);
            result = result.Replace(",\"SkipUnresolvedJsonWebKeys\":true", "");
            return result;
        }
    }

}