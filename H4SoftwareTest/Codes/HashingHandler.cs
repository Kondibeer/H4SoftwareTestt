using BCrypt.Net;
using System.Security.Cryptography;
using System.Text;

namespace H4SoftwareTest.Codes;

public static class HashingHandler
{
    public static string MD5Hashing(string txtToHash)
    {
        MD5 md5 = MD5.Create();

        byte[] txtToHashAsByteArray = Encoding.ASCII.GetBytes(txtToHash);
        byte[] hashedValue = md5.ComputeHash(txtToHashAsByteArray);

        
        return Convert.ToBase64String(hashedValue);
    }

    public static string SHA2Hashing(string txtToHash)
    {
        SHA256 sha256 = SHA256.Create();

        byte[] txtToHashAsByteArray = Encoding.ASCII.GetBytes(txtToHash);
        byte[] hashedValue = sha256.ComputeHash(txtToHashAsByteArray);

        return Convert.ToBase64String(hashedValue);
        
    }

    public static string HMACHashing(string txtToHash)
    {
        byte[] myKey = Encoding.ASCII.GetBytes(txtToHash);

        byte[] txtToHashAsByteArray = Encoding.ASCII.GetBytes(txtToHash);

        HMACSHA256 hmac = new HMACSHA256();
        hmac.Key = myKey;

        byte[] hashedValue = hmac.ComputeHash(txtToHashAsByteArray);
        return Convert.ToBase64String(hashedValue);
    }

    public static string PBKDF2Hashing(string txtToHash)
    {
        byte[] salt = Encoding.ASCII.GetBytes(txtToHash);
        byte[] txtToHashAsByteArray = Encoding.ASCII.GetBytes(txtToHash);
        var hashAlgo = new HashAlgorithmName("SHA256");
        int itirationer = 10;
        int outputLength = 32;

        byte[] hashedValue = Rfc2898DeriveBytes.Pbkdf2(txtToHashAsByteArray, salt, itirationer, hashAlgo, outputLength);

        return Convert.ToBase64String(hashedValue);
        
    }

    public static string BCryptHashing(string txtToHash)
    {
       
        string salt = BCrypt.Net.BCrypt.GenerateSalt();
        bool enhancedEntropy = true;
        HashType hashType = HashType.SHA256;
        return BCrypt.Net.BCrypt.HashPassword(txtToHash, salt, enhancedEntropy, hashType);

    }

    public static bool BCryptHashingVerify(string txtToHash, string hashedValueAsString)
    {

        bool enhanceEntropy = true;

        HashType hashType = HashType.SHA256;

        return BCrypt.Net.BCrypt.Verify(txtToHash, hashedValueAsString, true, HashType.SHA256);
    }
}

