//*********************************************************
//
// Copyright (c) Microsoft. All rights reserved.
// This code is licensed under the MIT License (MIT).
// THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
// IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
// PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************
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
