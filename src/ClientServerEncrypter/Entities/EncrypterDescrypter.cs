using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace ClientServerEncrypter.Entities
{
    public class EncrypterDescrypter
    {
        private static string privateKey;
        private static string publicKey;
        private static UnicodeEncoding _encoder = new UnicodeEncoding();
        private RNGCryptoServiceProvider rng;

        private TripleDES internalDes;
        private MD5 md5;
        private string internalDesKey;
        private byte[] internalDesIV;
        private byte[] externalDIV;
        private string externalPublicKey;

        public EncrypterDescrypter()
        {
            /*
             * Setup RSA
             */ 
            var rsa = new RSACryptoServiceProvider();
            privateKey = rsa.ToXmlString(true);
            publicKey = rsa.ToXmlString(false);
            /*
             * Setup Des
             */
            rng = new RNGCryptoServiceProvider();
            md5 = new MD5CryptoServiceProvider();
            internalDesKey = GenerateDKey();
            internalDesIV = GenerateDIV();
            internalDes = CreateDes(internalDesKey, internalDesIV);
        }
        /// <summary>
        /// Gets the internal Des IV
        /// </summary>
        public byte[] IV { get { return internalDesIV; } }
        /// <summary>
        /// Gets the public key
        /// </summary>
        public string PublicKey { get { return publicKey; } }
        public string ExternalPublicKey { get { return externalPublicKey; } }
        #region Des

        private TripleDES CreateDes(string key, byte[] iv)
        {
            var tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = md5.ComputeHash(_encoder.GetBytes(key));
            tdes.IV = iv;
            return tdes;
        }

        private static string GenerateDKey()
        {
            return "myprivatekey";
        }

        private byte[] GenerateDIV()
        {
            // The array is now filled with cryptographically strong random bytes.
            var IV = new Byte[8];
            rng.GetBytes(IV);
            return IV;
        }

        /// <summary>
        /// Cript the public key
        /// </summary>
        /// <returns></returns>
        public byte[] EncryptPublicKey()
        {
            ICryptoTransform ct = internalDes.CreateEncryptor();
            byte[] input = _encoder.GetBytes(publicKey);
            return ct.TransformFinalBlock(input, 0, input.Length);
        }

        /// <summary>
        /// Decrypt the public key using the remote IV
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="externalIv"></param>
        /// <returns></returns>
        public void DecryptPublicKey(byte[] publicKey, byte[] externalIv)
        {
            externalDIV = externalIv;
            var des = CreateDes(internalDesKey, externalDIV);
            byte[] b = publicKey;
            ICryptoTransform ct = des.CreateDecryptor();
            byte[] output = ct.TransformFinalBlock(b, 0, b.Length);
            externalPublicKey = _encoder.GetString(output);
        }
        #endregion
        public bool CheckExternalKey()
        {
            return !string.IsNullOrWhiteSpace(this.externalPublicKey);
        }

        #region RSA Methods

        /// <summary>
        /// Decript external message with my private key
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public string DecryptMessage(string data)
        {
            var rsa = new RSACryptoServiceProvider();
            var dataArray = data.Split(new char[] { ',' });
            byte[] dataByte = dataArray.Select(b => Convert.ToByte(b)).ToArray();
            rsa.FromXmlString(privateKey);
            var decryptedByte = rsa.Decrypt(dataByte, false);
            return _encoder.GetString(decryptedByte);
        }

        /// <summary>
        /// Encrypt message with the external public key
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public string EncryptMessage(string data)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(externalPublicKey);
            var dataToEncrypt = _encoder.GetBytes(data);
            var encryptedByteArray = rsa.Encrypt(dataToEncrypt, false).ToArray();
            return string.Join(",", encryptedByteArray);
        }
        #endregion
    }
}
