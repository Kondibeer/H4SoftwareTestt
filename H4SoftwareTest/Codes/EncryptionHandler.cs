using Microsoft.AspNetCore.DataProtection;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Text;

namespace H4SoftwareTest.Codes;

public class EncryptionHandler
{
    private readonly IDataProtector _dataProtector;
    private readonly string _privateKeyPath ="privateKey.Xml";
    private readonly string _publicKeyPath ="publicKey.Xml";
    private readonly HttpClient _httpClient;
    private string _privateKey;
    private string _publicKey;

    public EncryptionHandler(IDataProtectionProvider dataProtector, HttpClient httpClient)
    {

        
        
        _httpClient = httpClient;
        if (File.Exists(_privateKeyPath) && File.Exists(_publicKeyPath))
        {
            _privateKey = File.ReadAllText(_privateKeyPath);
            _publicKey = File.ReadAllText(_publicKeyPath);
        }
        else 
        {
            using (var rsa = new RSACryptoServiceProvider(2048)) 
            {
                _privateKey = rsa.ToXmlString(true);
                _publicKey = rsa.ToXmlString(false);
            }
        }


        _dataProtector = dataProtector.CreateProtector(_privateKey);

    }

    #region Symetric encryption

    public string EncryptSymetrisc(string txtToEncrypt) => _dataProtector.Protect(txtToEncrypt);

    public string DecryptSymetrisc(string txtToDecrypt) => _dataProtector.Unprotect(txtToDecrypt);

    #endregion

    #region Asymetric encryption

    //public async Task<string> EncryptAsymetriscParent(string txtToEncrypt)
    //{
    //    string[] data = new string[2] { txtToEncrypt, _publicKey };
    //    string serializedValue = JsonConvert.SerializeObject(data);
    //    StringContent content = new StringContent(serializedValue, System.Text.Encoding.UTF8, "application/json");
    //    var response = await _httpClient.PostAsync("https://localhost:7040/api/Encrypt", content);
    //    string encryptedValue = await response.Content.ReadAsStringAsync();
    //    return encryptedValue;
    //}

    public string EncryptAsymetrisc(string txtToEncrypt)
    {
        

        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        rsa.FromXmlString(_publicKey);

        byte[] txtToEncryptAsByteArry = System.Text.Encoding.UTF8.GetBytes(txtToEncrypt);
        byte[] encryptedValue = rsa.Encrypt(txtToEncryptAsByteArry, true);

        string encryptedValueAsString = Convert.ToBase64String(encryptedValue);

        return encryptedValueAsString;
    }
    public string DecryptAsymmetric(string txtToDecrypt)
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        rsa.FromXmlString(_privateKey);

        byte[] txtToDecryptAsByteArray = Convert.FromBase64String(txtToDecrypt);
        byte[] decryptedValue = rsa.Decrypt(txtToDecryptAsByteArray, true);
        string decryptedValueAsString = Encoding.UTF8.GetString(decryptedValue);

        return decryptedValueAsString;
    }



    #endregion
}
