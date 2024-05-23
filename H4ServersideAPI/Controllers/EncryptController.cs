using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace H4ServersideAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EncryptController : ControllerBase
    {
        [HttpPost]
        public string Post([FromBody] string[] value)
        {
            string txtToEncrypt = value[0];
            string publicKey = value[1];

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publicKey);

            byte[] txtToEncryptAsByteArray = System.Text.Encoding.UTF8.GetBytes(txtToEncrypt);
            byte[] encryptedValue = rsa.Encrypt(txtToEncryptAsByteArray, true);

            string encryptedValueAsString = Convert.ToBase64String(encryptedValue);

            return encryptedValueAsString;
        }
    }
}
