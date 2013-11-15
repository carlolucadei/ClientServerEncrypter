using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ClientServerEncrypter.Entities;

namespace ClientServerEncrypter
{

    public static class Extension
    {
        public static string ToComma(this byte[] item)
        {
            return string.Join(",", item);
        }
    }
    
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("First test...");
            Execute(new Negotiation(), new Negotiation());
            Console.WriteLine("");
            Console.WriteLine("Second test...");
            Execute(new Negotiation(), new Negotiation());
            Console.ReadKey();
        }

        private static void Execute(Negotiation client, Negotiation server)
        {
            // The client request the public key and the IV
            client.GetPublicKey(server.SendPublicKey(), server.IV);
            server.GetPublicKey(client.SendPublicKey(), client.IV);
            // The client sent the message to the server
            Console.WriteLine("The server IV is: '" + server.IV.ToComma() + "'");
            Console.WriteLine("The client IV is: '" + client.IV.ToComma() + "'");

            var clientMessage = "first message";
            Console.WriteLine("The client send the message: '" + clientMessage + "'");
            var clientEncryptMessage = client.SendMessage(clientMessage);
            Console.WriteLine("The message has been encrypted in: '" + clientEncryptMessage + "'");
            var decryptClientMessage = server.GetMessage(clientEncryptMessage);
            Console.WriteLine("The server decript the message in: '" + decryptClientMessage + "'");
            var serverMessage = "got it";
            Console.WriteLine("The server now sent a new message to the client: '" + serverMessage + "'");
            var serverEncryptedMessage = server.SendMessage(serverMessage);
            Console.WriteLine("The message has been encrypted in: '" + serverEncryptedMessage + "'");
            var decryptServerMessage = client.GetMessage(serverEncryptedMessage);
            Console.WriteLine("The client decript the message sent by the server in: '" + decryptServerMessage + "'");
        }
    }
}
