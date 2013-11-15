using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ClientServerEncrypter.Entities
{
    public class Negotiation : EncrypterDescrypter
    {
        public byte[] SendPublicKey()
        {
            return base.EncryptPublicKey();
        }
        public void GetPublicKey(byte[] key, byte[] iv){
            this.DecryptPublicKey(key, iv);
        }

        public string SendMessage(string message)
        {
            if (!this.CheckExternalKey())
                throw new InvalidOperationException("Cannot send message with a not valid public key");
            return this.EncryptMessage(message);
        }

        public string GetMessage(string message)
        {
            return this.DecryptMessage(message);
        }
    }
}
