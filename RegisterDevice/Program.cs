using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Security.Cryptography;
using System.Globalization;
using Microsoft.Extensions.Configuration;


namespace RegisterDevice
{
    class Program
    {
        static int Main(string[] args)
        {
            return MainAsync(args).Result;
        }
        public static string generateSasToken(string resourceUri, string key, string deviceId, int expiryInSeconds = 3600)
        {
            TimeSpan fromEpochStart = DateTime.UtcNow - new DateTime(1970, 1, 1);
            string expiry = Convert.ToString((int)fromEpochStart.TotalSeconds + expiryInSeconds);

            string stringToSign = WebUtility.UrlEncode(resourceUri) + "\n" + deviceId + "\n" + expiry ; 
            //deviceId is added to the signature string so the signature is only valid for exactly this device to avoid replay with different device ID

            HMACSHA256 hmac = new HMACSHA256(Convert.FromBase64String(key));
            string signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));

            string token = String.Format(CultureInfo.InvariantCulture, "sr={0}&sig={1}&se={2}", WebUtility.UrlEncode(resourceUri), WebUtility.UrlEncode(signature), expiry);

            return token;
        }
        static async System.Threading.Tasks.Task<int> MainAsync(string[] args)
        {

            var builder = new ConfigurationBuilder().AddJsonFile("appsettings.json");

            
            var configuration = builder.Build();
            var setting = configuration["functionKey"];
            string functionKey = configuration["functionKey"];
            string validationKey = configuration["validationKey"];
            string serviceurl = configuration["serviceURL"];
            string serialNumber = args[0];
            HttpClient client = new HttpClient();

            client.BaseAddress = new Uri(serviceurl);
            client.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));

            string sas = generateSasToken(serviceurl, validationKey, serialNumber);

            HttpResponseMessage response = client.GetAsync("?code=" + functionKey + "&SerialNumber="+serialNumber+"&"+sas).Result;

            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine("ERROR:");
                Console.WriteLine(response.ReasonPhrase);
                Console.WriteLine(await response.Content.ReadAsStringAsync());
                return -1;
            }

            // return URI of the created resource.
            string connectionString = await response.Content.ReadAsStringAsync();
            if (connectionString[0]=='\"')
            {
                connectionString = connectionString.Substring(1, connectionString.Length - 2);
            }
            Console.WriteLine("connection string=\""+connectionString+"\"");
            return 0;

        }
    }
}
