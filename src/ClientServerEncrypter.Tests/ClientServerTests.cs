using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using ClientServerEncrypter.Entities;

namespace ClientServerEncrypter.Tests
{
    [TestClass]
    public class ClientServerTests
    {
        Negotiation client;
        Negotiation server;

        [TestInitialize]
        public void SetUp()
        {
            client = new Negotiation();
            server = new Negotiation();
        }
        [TestCleanup]
        public void TearDown()
        {
        }
        [TestMethod]
        public void ClientSents_PublicKey()
        {
            server.GetPublicKey(client.SendPublicKey(), client.IV);
            Assert.AreEqual(client.PublicKey, server.ExternalPublicKey);
        }

        [TestMethod]
        public void ServerSents_PublicKey()
        {
            client.GetPublicKey(server.SendPublicKey(), server.IV);
            Assert.AreEqual(server.PublicKey, client.ExternalPublicKey);
        }
        [TestMethod]
        public void Client_SentMessage()
        {
            string clientMessage = "Hello world!";
            /*
             * Exchange encrypted public key
             */ 
            client.GetPublicKey(server.SendPublicKey(), server.IV);
            server.GetPublicKey(client.SendPublicKey(), client.IV);
            // The server received the message and decode it
            var decryptClientMessage = server.GetMessage(client.SendMessage(clientMessage));
            Assert.AreEqual(clientMessage, decryptClientMessage);
        }
        [TestMethod]
        public void Server_SentMessage()
        {
            string serverMessage = "Got it!";
            /*
             * Exchange encrypted public key
             */ 
            client.GetPublicKey(server.SendPublicKey(), server.IV);
            server.GetPublicKey(client.SendPublicKey(), client.IV);
            // The server received the message and decode it
            var decryptServerMessage = client.GetMessage(server.SendMessage(serverMessage));
            Assert.AreEqual(serverMessage, decryptServerMessage);
        }
        [TestMethod]
        public void Client_SentAlwaysTheSameMessage()
        {
            string clientMessage = "Hello world!";
            /*
             * Exchange encrypted public key
             */
            client.GetPublicKey(server.SendPublicKey(), server.IV);
            server.GetPublicKey(client.SendPublicKey(), client.IV);
            // The server received the message and decode it
            var encryptedClientMessage1 = client.SendMessage(clientMessage);
            var encryptedClientMessage2 = client.SendMessage(clientMessage);
            Console.WriteLine(encryptedClientMessage1);
            Console.WriteLine(encryptedClientMessage2);
            //Assert.AreEqual(encryptedClientMessage1, encryptedClientMessage2);
        }
        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void Client_DoNotSent_PublicKey()
        {
            string clientMessage = "Hello world!";
            // The server received the message and decode it
            var decryptClientMessage = server.GetMessage(client.SendMessage(clientMessage));
        }
        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void Server_DoNotSent_PublicKey()
        {
            string serverMessage = "Got it!";
            // The server received the message and decode it
            var decryptServerMessage = client.GetMessage(server.SendMessage(serverMessage));
        }
    }
}
