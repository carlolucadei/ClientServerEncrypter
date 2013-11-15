using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace ClientServerEncrypter.Entities
{
    public class EncrypterDescrypter
    {
        private static string _privateKey;
        private static string _publicKey;
        private static UnicodeEncoding _encoder = new UnicodeEncoding();
        
        RNGCryptoServiceProvider rng;

        private TripleDES internalDes;
        private MD5 md5;
        private string DKey;
        private byte[] DIV;
        private byte[] externalDIV;
        private string externalPublicKey;

        public EncrypterDescrypter()
        {
            /*
             * Setup RSA
             */ 
            var rsa = new RSACryptoServiceProvider();
            _privateKey = rsa.ToXmlString(true);
            _publicKey = rsa.ToXmlString(false);
            /*
             * Setup Des
             */
            rng = new RNGCryptoServiceProvider();
            md5 = new MD5CryptoServiceProvider();
            DKey = GenerateDKey();
            DIV = GenerateDIV();
            internalDes = CreateDes(DKey, DIV);
        }

        public byte[] IV { get { return DIV; } }
        public string PublicKey { get { return _publicKey; } }

        private TripleDES CreateDes(string key, byte[] iv)
        {
            var tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = md5.ComputeHash(Encoding.Unicode.GetBytes(key));
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
            //return System.Text.Encoding.UTF8.GetString(IV);
        }

        public bool CheckExternalKey()
        {
            return !string.IsNullOrWhiteSpace(this.externalPublicKey);
        }

        /// <summary>
        /// Cript the public key
        /// </summary>
        /// <returns></returns>
        public byte[] EncryptPublicKey()
        {
            ICryptoTransform ct = internalDes.CreateEncryptor();
            byte[] input = Encoding.Unicode.GetBytes(_publicKey);
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
            var des = CreateDes(DKey, externalDIV);
            byte[] b = publicKey;
            ICryptoTransform ct = des.CreateDecryptor();
            byte[] output = ct.TransformFinalBlock(b, 0, b.Length);
            externalPublicKey = Encoding.Unicode.GetString(output);
        }

        /// <summary>
        /// Decript external message with my private key
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public string DecryptMessage(string data)
        {
            var rsa = new RSACryptoServiceProvider();
            var dataArray = data.Split(new char[] { ',' });
            byte[] dataByte = new byte[dataArray.Length];
            for (int i = 0; i < dataArray.Length; i++)
                dataByte[i] = Convert.ToByte(dataArray[i]);
            rsa.FromXmlString(_privateKey);
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
    }
}
