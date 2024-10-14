using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json;
using System.Diagnostics;

namespace JwtTokenGeneratorApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class JwtTokenController : ControllerBase
    {
        private readonly Dictionary<string, RSA> _privateKeys = new Dictionary<string, RSA>();

        public JwtTokenController(IWebHostEnvironment env)
        {
            // Get the absolute path to the 'Keys.json' file in the project root
            string keysFilePath = Path.Combine(env.ContentRootPath, "Keys.json");

            // Load the private keys from the JSON file
            string jsonString = System.IO.File.ReadAllText(keysFilePath);
            dynamic? jsonData = JsonConvert.DeserializeObject(jsonString);

            if (jsonData?.data is not null)
            {
                foreach (var keyEntry in jsonData.data)
                {
                    string keyId = keyEntry.keyId;
                    string privateKeyPem = keyEntry.private_key;

                    // Create RSA instance for each key pair
                    RSA rsaPrivateKey = RSA.Create();
                    rsaPrivateKey.ImportFromPem(privateKeyPem.ToCharArray());

                    // Store the RSA instance in the dictionary, keyed by keyId
                    _privateKeys[keyId] = rsaPrivateKey;
                }
            }
            else
            {
                throw new InvalidOperationException("No 'data' field found in the JSON.");
            }
        }

        // Endpoint to generate JWT for Google Sheets API access
        [HttpPost("generateJwt")]
        public IActionResult GenerateGoogleJwt([FromBody] JObject requestData)
        {
            if (requestData == null)
            {
                return BadRequest("Invalid request data.");
            }

            try
            {
                var encryptedDataBase64 = requestData["data"]?.ToString();
                var encryptedSymmetricKeyBase64 = requestData["symmetricKey"]?.ToString();
                var ivBase64 = requestData["iv"]?.ToString(); // Extract the IV
                var keyId = requestData["keyId"]?.ToString();

                if (string.IsNullOrEmpty(encryptedDataBase64) || string.IsNullOrEmpty(encryptedSymmetricKeyBase64) || string.IsNullOrEmpty(ivBase64) || string.IsNullOrEmpty(keyId))
                {
                    return BadRequest("Encrypted data, IV, or key ID is missing.");
                }

                // Check if the specified keyId exists in the key store
                if (!_privateKeys.ContainsKey(keyId))
                {
                    return BadRequest("Invalid key ID.");
                }

                // Decrypt the symmetric key using the RSA private key
                var privateKey = _privateKeys[keyId];
                var symmetricKeyBytes = DecryptSymmetricKeyWithPrivateKey(privateKey, Convert.FromBase64String(encryptedSymmetricKeyBase64));

                // Convert the IV from Base64 to byte array
                var ivBytes = Convert.FromBase64String(ivBase64);

                // Convert the encrypted data from Base64 to byte array
                var encryptedDataBytes = Convert.FromBase64String(encryptedDataBase64);

                // Extract the tag (last 16 bytes for AES-GCM)
                if (encryptedDataBytes.Length < 16)
                {
                    return BadRequest("Encrypted data is too short to contain a valid tag.");
                }

                var tagLength = 16; // AES-GCM uses a 16-byte tag
                var tagBytes = new byte[tagLength];
                Array.Copy(encryptedDataBytes, encryptedDataBytes.Length - tagLength, tagBytes, 0, tagLength);

                // Extract the ciphertext (remaining bytes before the tag)
                var ciphertextLength = encryptedDataBytes.Length - tagLength;
                var ciphertextBytes = new byte[ciphertextLength];
                Array.Copy(encryptedDataBytes, 0, ciphertextBytes, 0, ciphertextLength);

                // Now decrypt the data using the recovered symmetric key, IV, and the ciphertext with the tag
                var decryptedData = /*DecryptDataWithAES(symmetricKeyBytes, ivBytes, tagBytes, ciphertextBytes)*/"";

                // Parse the decrypted data into service account info
                JObject serviceAccountInfo = JObject.Parse(decryptedData);

                // Extract the required fields from the service account info
                var privateKeyPem = serviceAccountInfo["private_key"]?.ToString();
                var clientEmail = serviceAccountInfo["client_email"]?.ToString();
                var tokenUri = serviceAccountInfo["token_uri"]?.ToString();

                if (string.IsNullOrEmpty(privateKeyPem) || string.IsNullOrEmpty(clientEmail) || string.IsNullOrEmpty(tokenUri))
                {
                    return BadRequest("Service account information is incomplete.");
                }

                // Create the RSA private key from the service account's private key
                var rsa = RSA.Create();
                rsa.ImportFromPem(privateKeyPem.ToCharArray());

                // Generate JWT using claims needed by Google API
                var jwt = GenerateJwtToken(rsa, clientEmail, tokenUri);

                return Ok(new { JwtToken = jwt });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"An error occurred: {ex.Message}");
            }
        }

        protected byte[] DecryptSymmetricKeyWithPrivateKey(RSA privateKey, byte[] encryptedSymmetricKey)
        {
            // Giải mã symmetric key bằng khóa riêng
            return privateKey.Decrypt(encryptedSymmetricKey, RSAEncryptionPadding.Pkcs1);
        }

        protected string DecryptDataWithAES(string secretKey, string ivString, string encryptedDataString)
        {
            // Convert the plain text key and IV to byte arrays
            byte[] key = Encoding.UTF8.GetBytes(secretKey);

            // Ensure the IV is 12 bytes
            byte[] iv = Encoding.UTF8.GetBytes(ivString.Substring(0, 12));

            // Convert the Base64-encoded encrypted data to a byte array
            byte[] encryptedData = Convert.FromBase64String(encryptedDataString);

            try
            {
                using (AesGcm aesGcm = new AesGcm(key))
                {
                    // Separate the tag and ciphertext
                    byte[] tag = new byte[16]; // AES-GCM tag size is 16 bytes (128 bits)
                    byte[] cipherText = new byte[encryptedData.Length - tag.Length]; // CipherText without tag

                    // Extract the tag (last 16 bytes of encryptedData)
                    Array.Copy(encryptedData, encryptedData.Length - tag.Length, tag, 0, tag.Length);

                    // Extract the ciphertext (everything except the tag)
                    Array.Copy(encryptedData, 0, cipherText, 0, cipherText.Length);

                    // Add logging to the unit test's output
                    Debug.WriteLine($"Key (Base64): {Convert.ToBase64String(key)}");
                    Debug.WriteLine($"IV (Base64): {Convert.ToBase64String(iv)}");
                    Debug.WriteLine($"Tag (Base64): {Convert.ToBase64String(tag)}");
                    Debug.WriteLine($"CipherText (Base64): {Convert.ToBase64String(cipherText)}");

                    // Decrypted data buffer
                    byte[] decryptedData = new byte[cipherText.Length];

                    // Decrypt the data
                    aesGcm.Decrypt(iv, cipherText, tag, decryptedData);

                    // Convert the decrypted byte array back to a string
                    string decryptedString = Encoding.UTF8.GetString(decryptedData);
                    Debug.WriteLine($"Decrypted Data: {decryptedString}");
                    return decryptedString;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Decryption failed: {ex.Message}");
                throw new Exception("Decryption failed.", ex);
            }
        }


        protected string GenerateJwtToken(RSA rsa, string clientEmail, string tokenUri)
        {
            // Define claims for JWT
            var claims = new[]
            {
                new Claim("iss", clientEmail),
                new Claim("scope", "https://www.googleapis.com/auth/spreadsheets"),
                new Claim("aud", tokenUri),
                new Claim("iat", GetUnixTimeSeconds(DateTime.UtcNow).ToString()),
                new Claim("exp", GetUnixTimeSeconds(DateTime.UtcNow.AddMinutes(60)).ToString())
            };

            var credentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);

            // Create JWT token
            var jwtSecurityToken = new JwtSecurityToken(
                issuer: clientEmail,
                audience: tokenUri,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(60),
                signingCredentials: credentials
            );

            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(jwtSecurityToken);
        }

        protected long GetUnixTimeSeconds(DateTime dateTime)
        {
            DateTimeOffset dto = new DateTimeOffset(dateTime);
            return (long)(dto.ToUniversalTime() - new DateTime(1970, 1, 1)).TotalSeconds;
        }

        protected string SignResponse(string jwtToken, RSA privateKey)
        {
            // Sign the server's JWT response using the selected private key
            byte[] dataBytes = Encoding.UTF8.GetBytes(jwtToken);
            byte[] signatureBytes = privateKey.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signatureBytes);
        }
    }
}
