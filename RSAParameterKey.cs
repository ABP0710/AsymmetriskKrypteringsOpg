using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AsymmetriskKrypteringsOpg
{
    public class RSAParameterKey
    {
        public RSAParameters publicKey;
        public RSAParameters privateKey;

        /// <summary>
        /// Create a new instance of RSA,
        /// to generate public and private key 
        /// </summary>
        public void AssingningNewKey()
        {            
            var rsa = RSA.Create();

            rsa.KeySize = 2048;

            publicKey = rsa.ExportParameters(false);
            privateKey = rsa.ExportParameters(true);
        }


        /// <summary>
        /// Method for encrypting the text,
        /// Create byte arrays to hold the encrypted text,
        /// Create a new instance of RSA,
        /// Import the RSA publicKey information,
        /// Encrypt the byte array and sets OAEP padding
        /// </summary>
        /// <param name="textToEncrypt"></param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] textToEncrypt)
        {
            byte[] encryptedText;

            try
            {
                var rsa = RSA.Create();

                rsa.ImportParameters(publicKey);
                encryptedText = rsa.Encrypt(textToEncrypt, RSAEncryptionPadding.OaepSHA256);

                return encryptedText;
            }
            catch (CryptographicException e)
            {
                Debug.WriteLine(e.Message);

                return null;
            }
        }

        /// <summary>
        /// Method for decrypting the cipher,
        /// Create byte arrays to hold the decrypted text,
        /// Create a new instance of RSA,
        /// Import the RSA privateKey information,
        /// Decrypt the byte array and sets OAEP padding
        /// </summary>
        /// <param name="textToEncrypt"></param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] textToEncrypt)
        {
            byte[] decryptedText;

            try
            {
                var rsa = RSA.Create();

                rsa.ImportParameters(privateKey);
                decryptedText = rsa.Decrypt(textToEncrypt, RSAEncryptionPadding.OaepSHA256);

                return decryptedText;
            }
            catch (CryptographicException e)
            {
                Debug.WriteLine(e.Message);

                return null;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="fs"></param>
        /// <param name="value"></param>
        private static void FileStreamForKey(FileStream fs, string value)
        {
            byte[] text = new UTF8Encoding(true).GetBytes(value);
            fs.Write(text, 0, text.Length);
        }
    }
}
