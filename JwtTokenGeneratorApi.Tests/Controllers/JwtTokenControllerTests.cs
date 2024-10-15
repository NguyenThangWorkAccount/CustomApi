using Xunit;
using JwtTokenGeneratorApi.Controllers;
using System.Security.Cryptography;
using System;
using Moq;
using Microsoft.AspNetCore.Hosting;
using System.Text;
using Newtonsoft.Json.Linq;
using Moq.Protected;
using System.Reflection;
using System.Security.Cryptography.Xml;

namespace JwtTokenGeneratorApi.Tests.Controllers;

// Derived class to expose protected methods for testing
public class TestableJwtTokenController : JwtTokenController
{
    public TestableJwtTokenController(IWebHostEnvironment env) : base(env) { }

    // Expose protected methods for testing
    public byte[] TestDecryptSymmetricKeyWithPrivateKey(string encryptedData, RSA privateKey) 
        => DecryptSymmetricKeyWithPrivateKey(privateKey, Convert.FromBase64String(encryptedData));
    //public string TestDecryptDataWithAESDecryptDataWithAES(byte[] symmetricKey, byte[] iv, string encryptedDataBase64) 
    //    => DecryptDataWithAES(symmetricKey, iv, encryptedDataBase64);
    public string TestGenerateJwtToken(RSA rsa, string clientEmail, string tokenUri) 
        => GenerateJwtToken(rsa, clientEmail, tokenUri);
    public long TestGetUnixTimeSeconds(DateTime dateTime)
        => GetUnixTimeSeconds(dateTime);
    public string TestSignResponse(string jwtToken, RSA privateKey) 
        => SignResponse(jwtToken, privateKey);
}


public class JwtTokenControllerTests
{
    private readonly TestableJwtTokenController _controller;

    public JwtTokenControllerTests()
    {
        // Mocking IWebHostEnvironment
        var mockEnv = new Mock<IWebHostEnvironment>();
        mockEnv.Setup(m => m.ContentRootPath).Returns(AppContext.BaseDirectory);

        _controller = new TestableJwtTokenController(mockEnv.Object);
    }

    #region Test DecryptSymmetricKeyWithPrivateKey Method

    [Theory]
    [InlineData("TestInput/private_key_1.pem", "","")]
    [InlineData("TestInput/private_key_2.pem", "","")]
    [InlineData("TestInput/private_key_3.pem", "","")]
    public void DecryptData_ShouldReturnDecryptedString(string symmetricKey, string encryptedData, string expectedJsonString)
    {
        // Arrange
        using var rsa = RSA.Create();
        string privateKeyPem = File.ReadAllText(symmetricKey); // Read the private key from the PEM file
        rsa.ImportFromPem(privateKeyPem.ToCharArray()); // Import the RSA key

        // Act
        var decryptedBytes = _controller.TestDecryptSymmetricKeyWithPrivateKey(encryptedData, rsa); // Decrypt the data
        var decryptedData = Encoding.UTF8.GetString(decryptedBytes); // Convert byte[] to string

        // Parse both the decrypted data and the expected result as JSON objects
        JObject actualJsonObject = JObject.Parse(decryptedData); // Convert decrypted string to JObject
        JObject expectedJsonObject = JObject.Parse(expectedJsonString); // Convert expected string to JObject

        // Assert: Compare the JSON objects
        Assert.Equal(expectedJsonObject, actualJsonObject);
    }


    //[Theory]
    //[InlineData(null)]
    //public void DecryptData_ShouldThrowArgumentNullException(byte[] encryptedData)
    //{
    //    // Arrange
    //    using var rsa = RSA.Create();

    //    // Act & Assert
    //    var exception = Assert.Throws<ArgumentNullException>(() => _controller.TestDecryptData(encryptedData, rsa));
    //    Assert.Contains("encryptedData", exception.Message); // Verify the exception message
    //}

    //[Theory]
    //[InlineData("InvalidData")]
    //public void DecryptData_ShouldThrowCryptographicException(string invalidBase64Data)
    //{
    //    // Arrange
    //    using var rsa = RSA.Create();
    //    var encryptedData = Encoding.UTF8.GetBytes(invalidBase64Data);

    //    // Act & Assert
    //    var exception = Assert.Throws<CryptographicException>(() => _controller.TestDecryptData(encryptedData, rsa));
    //    Assert.Contains("Error decrypting data", exception.Message); // Verify the exception message
    //}

    #endregion

    #region Test DecryptDataWithAES Method

    [Theory]
    //[InlineData(
    //    "JvnEcwo7hzuowYRJvGa1tPHfnSQwfXk8YZOaqvm5kBo=",
    //    "XeTHTFf63H41fSc0",
    //    "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\",\r\n  \"symmetricKey\": \"KSMAE5qpzRLNSK/YphggauZifk9Pco2aenFuduOeOPY=",
    //    "{\r\n    private_key: \"-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5Dfrwp4Id9kvf\\nbn6uKM5jmaCfHDvAERTkqBh+OqL6seMi+Kkzqf7lVghRBPdKNzF4UZSc+s50njv/\\nnCDOEEH138QD04RnLGA3vjGecCEB93N1YqCVy+dYcW5dQstXOKaXOekwA3G5mFsy\\nPXRWleHDhQh4dw+/x3AkzdXuctdbBACx2c/cIgApJL86Xynfai2gH+uMLgBjUy9n\\nNxzu9Qplq8xL8qeOTaZLMmEdS0YS7pHm/0i4rNf/FOg5Uubvff2IMd9DWlQbfa1C\\nz4m5spK2Fmpk+odTiURez7/+3agllet4KoMSk7OxVSJXvIigFJG7aeiIOE8gslcX\\nHlqbTmbjAgMBAAECggEAC4dPmlLShtuot2cyqivtoQPZn1VKyE49dHn1E1bDf4W5\\n25xigiRK4RkJKe76xEYIUBwY+5HzxGJ1Ohk3wU6ppU/cQ3bCbrZeL4Aq/C61HQ0V\\nmtBa+79juWf7qFYNxUXIucQdqbmVNKrwB4MPmTNQ3iA5ZQkvKH3xbRbhBzANXY9D\\np6jGYNM75sXJrHuKU1nR+wRpjDU5U2rVSiRHZQr/DYyseLJ/L5owgsB3YB13aXl2\\nRL4HSLO9oPnJ9nC7svE19tAp2OdHKI8q1ZowTI3Ir4gUvu8B18tjhZ4/fj5ammLN\\nAdUxC0dgs0kupG5wJE+NOTHaTC0A8ndKfixUvJ9U/QKBgQDdL1TrsI++bGasG5CC\\nHOEdx683LuEcbpqybj7PpJNtsvsYICNOsb9MtPqww3UCDfFAEwgltXigtAMovCmD\\nOgd/BRdEHF0LHlQZ0+WP4hr+CaU/Go89EglQ23egw8WAUr0iRZr4YiRnqcbuGrv1\\niJ2QrF+cHjklYTOSFaXc25SHzwKBgQDWLsZu1r/+apIXyPybT11JL49x9Lp9m5Hp\\n6wZlo++4Gy26uJkLYIpJxM5k/9wVtShOphSgMTGqkSIN5K4cB6uWXlpSWgKZtNuH\\nk4JjgqsI2aodtwNFkNAtzd52qy7XnQCuZ7VugbdvulCFSzhSdkydoUbA9Bv/go4k\\n+7E4ii9grQKBgQDIfxI8f5UdaUf8tRPeTe1mQE8893rJeh0ypyq6sJWPeBGSgfdf\\na1JcZyVjvBnBnf/VNCtLe194VRUUBNSghqaq5mN7szZIUNqtet35+ly7cOTg+eNj\\n2YimSfr7uNq8AsQ9X9klVFlpuoV/6q382TTzIr2cV+03TBAiWQs707OlEwKBgQCK\\nW+0T7OZaE74MX2nPapV4kaC4nL9cJQM9ePXI8v4IkIYZ+OXk05iBzwEFfcNOwpgn\\nNmJcmWrcJKU7FF7k/I97s7flOwAzCwJFsqSoY+DY9sNOLsuORN42uKbdQfggkOu/\\nvn8Vw/Yb1t/tO4pGuuUDbwul2gu8Izpv6aeyPpIcgQKBgGMbphS/fXy239913lGR\\n2PtqzaH96djIU2Ow92lqrY4pnZ4o0fEppao4KmPhQIbxq2cxzaTDNjIwN89g202q\\nDpTGHi+HvPhDTGARLmz32MZguNFhmaM9s3U7+eqU+YNpT898/nWF7oxxcl3M913C\\nKKnUuCrE3v7pCzSgfeEF1FjB\\n-----END PRIVATE KEY-----\\n\",\r\n    client_email: \"test1-448@wordpressadministrationproject.iam.gserviceaccount.com\",\r\n    token_uri: \"https://oauth2.googleapis.com/token\"\r\n}")]

    [InlineData(
        "testSecretKey001", // 128-bit key
        "testinitialvecto", // IV will be truncated to "testinitialve"
        "OFKAIngelJI+hTQ2f+ryKRYc+aOvJueoMPjNPabiPjbnyJXO6wo=", // Encrypted data
        "{\"data\":\"Hello world\"}" // Expected result
    )]
    public void DecryptDataWithAES_ShouldReturnDecryptedString(string symmetricKey, string iv, string encryptedData, string expectedJsonString)
    {
        // Arrange

        // Mocking IWebHostEnvironment
        var mockEnv = new Mock<IWebHostEnvironment>();
        mockEnv.Setup(m => m.ContentRootPath).Returns(AppContext.BaseDirectory);

        var mockController = new Mock<JwtTokenController>(mockEnv.Object) { CallBase = true }; // Enable calling base methods
        var controller = mockController.Object;

        // Act: Invoke the protected method directly
        var methodInfo = controller.GetType().GetMethod("DecryptDataWithAES", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(methodInfo);

        var decryptedString = methodInfo.Invoke(controller, new object[] { symmetricKey, iv, encryptedData });

        // Assert
        Assert.NotNull(decryptedString);
        var result = JObject.Parse(decryptedString.ToString());
        var expectedJson = JObject.Parse(expectedJsonString);
        Assert.Equal(expectedJsonString, decryptedString); // Compare the decrypted string to the expected JSON string
    }



    // Additional test cases for invalid input

    //[Theory]
    //[InlineData(null, "BASE64_ENCRYPTED_DATA", "Expected argument null exception for symmetric key")]
    //[InlineData("BASE64_SYMMETRIC_KEY", null, "Expected argument null exception for encrypted data")]
    //[InlineData("INVALID_SYMMETRIC_KEY", "BASE64_ENCRYPTED_DATA", "Expected cryptographic exception due to invalid symmetric key format")]
    //[InlineData("BASE64_SYMMETRIC_KEY", "INVALID_ENCRYPTED_DATA", "Expected cryptographic exception due to invalid Base64 string format")]
    //public void DecryptDataWithAESDecryptDataWithAES_ShouldHandleInvalidInput(string symmetricKey, string iv, string encryptedData, string expectedMessage)
    //{
    //    // Arrange
    //    if (symmetricKey != null)
    //    {
    //        byte[] key = Convert.FromBase64String(symmetricKey); // Convert the Base64 string to byte array
    //    }

    //    // Act & Assert
    //    if (symmetricKey == null || encryptedData == null)
    //    {
    //        var exception = Assert.Throws<ArgumentNullException>(() => _controller.TestDecryptDataWithAESDecryptDataWithAES(null, encryptedData));
    //        Assert.Contains("symmetricKey", exception.Message);
    //    }
    //    else
    //    {
    //        Assert.Throws<CryptographicException>(() => _controller.TestDecryptDataWithAESDecryptDataWithAES(Convert.FromBase64String(symmetricKey), encryptedData));
    //    }
    //}

    #endregion

    #region Test GenerateJwtToken Method

    [Theory]
    [InlineData("test@example.com", "https://example.com/token")]
    [InlineData("other@example.com", "https://another.com/token")]
    public void GenerateJwtToken_ShouldReturnValidJwt(string clientEmail, string tokenUri)
    {
        // Arrange
        using var rsa = RSA.Create(); // Use a valid RSA key for testing

        // Act
        var jwt = _controller.TestGenerateJwtToken(rsa, clientEmail, tokenUri);

        // Assert
        Assert.NotNull(jwt);
        Assert.Contains("eyJ", jwt); // Check if the returned string starts with JWT prefix
    }

    [Theory]
    [InlineData(null, "https://example.com/token")]
    [InlineData("test@example.com", null)]
    public void GenerateJwtToken_ShouldThrowArgumentNullException(string clientEmail, string tokenUri)
    {
        // Arrange
        using var rsa = RSA.Create(); // Use a valid RSA key for testing

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() => _controller.TestGenerateJwtToken(rsa, clientEmail, tokenUri));
        Assert.Contains("clientEmail", exception.Message); // Verify the exception message
    }

    #endregion

    #region Test GetUnixTimeSeconds Method

    [Theory]
    [InlineData("2024-01-01T00:00:00Z", 1704067200)]  // Unix time for 2024-01-01
    [InlineData("2023-12-31T23:59:59Z", 1704067199)]  // Unix time just before 2024-01-01
    public void GetUnixTimeSeconds_ShouldReturnCorrectUnixTime(string dateTimeStr, long expectedUnixTime)
    {
        // Arrange
        var dateTime = DateTime.Parse(dateTimeStr).ToUniversalTime();

        // Act
        var unixTime = _controller.TestGetUnixTimeSeconds(dateTime);

        // Assert
        Assert.Equal(expectedUnixTime, unixTime);
    }

    [Theory]
    [InlineData("InvalidDateTime")]
    public void GetUnixTimeSeconds_ShouldThrowFormatException(string invalidDateTime)
    {
        // Arrange
        var dateTime = DateTime.Parse(invalidDateTime);

        // Act & Assert
        var exception = Assert.Throws<FormatException>(() => _controller.TestGetUnixTimeSeconds(dateTime));
        Assert.Contains("String was not recognized as a valid DateTime", exception.Message); // Verify exception message
    }

    #endregion

    #region Test SignResponse Method

    [Theory]
    [InlineData("testJwtToken")]
    public void SignResponse_ShouldReturnValidSignature(string jwtToken)
    {
        // Arrange
        using var rsa = RSA.Create(); // Use a valid RSA key for testing
        rsa.ImportFromPem("your-private-key-here".ToCharArray()); // Replace with your private key for testing

        // Act
        var signature = _controller.TestSignResponse(jwtToken, rsa);

        // Assert
        Assert.NotNull(signature);
        Assert.True(Convert.FromBase64String(signature).Length > 0); // Check if the signature is not empty
    }

    [Theory]
    [InlineData(null)]
    public void SignResponse_ShouldThrowArgumentNullException(string jwtToken)
    {
        // Arrange
        using var rsa = RSA.Create(); // Use a valid RSA key for testing

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() => _controller.TestSignResponse(jwtToken, rsa));
        Assert.Contains("jwtToken", exception.Message); // Verify the exception message
    }

    #endregion
}