using System;
using Microsoft.Azure.Devices.Common;
using System.Configuration;
using System.Security.Cryptography;

namespace GenKey
{
    class Program
    {
        static void Main(string[] args)
        {
            var key = CryptoKeyGenerator.GenerateKey(40);
            Console.WriteLine("This is your SAS generation and validation key:");
            Console.WriteLine();
            Console.WriteLine(key);
            Console.WriteLine();
            Console.WriteLine("Put the following line in appsettings.json of the client program");
            Console.WriteLine();
            Console.WriteLine("\"validationKey\": \"" + key + "\"");
            Console.WriteLine();
            Console.WriteLine("and as an application setting in your azure function app");
        }
    }
}
