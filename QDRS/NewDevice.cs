using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.Azure.Devices;
using System;
using Microsoft.Azure.Devices.Common;
using System.Configuration;
using System.Security.Cryptography;
using System.Globalization;


namespace QDRS
{
    public static class NewDevice
    {
        [FunctionName("NewDevice")]
        public static async Task<HttpResponseMessage> Run([HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)]HttpRequestMessage req, TraceWriter log)
        {
            log.Info("C# HTTP trigger function processed a request.");
            var IoTHubConnectionString = ConfigurationManager.AppSettings["IoTHub"];
            var validationKey = ConfigurationManager.AppSettings["validationKey"];
            RegistryManager rm;
            try
            {
                rm = RegistryManager.CreateFromConnectionString(IoTHubConnectionString);
            }
            catch (Exception ex)
            {
                log.Info("Cannot access IoT Hub");
                return req.CreateResponse(HttpStatusCode.InternalServerError, "Cannot access IoT Hub");
            }

            // Parsing and validating function arguments

            // parse query parameter
            string SerialNumber = req.GetQueryNameValuePairs()
                .FirstOrDefault(q => string.Compare(q.Key, "SerialNumber", true) == 0)
                .Value;

            
            if (SerialNumber == null)
            {
                // Get request body
                dynamic data = await req.Content.ReadAsAsync<object>();
                SerialNumber = data?.SerialNumber;
            }
            if (SerialNumber == null)
            {
                log.Info("No serial number given");
                return req.CreateResponse(HttpStatusCode.BadRequest, "Please pass a SerialNumber on the query string or in the request body");
            }

            log.Info("Creating device for serial number \"" + SerialNumber + "\"");

            string sr = req.GetQueryNameValuePairs()
                .FirstOrDefault(q => string.Compare(q.Key, "sr", true) == 0)
                .Value;
            if (sr == null)
            {
                // Get request body
                dynamic data = await req.Content.ReadAsAsync<object>();
                sr = data?.sr;
            }
            if (sr == null)
            {
                log.Info("No sr given");
                return req.CreateResponse(HttpStatusCode.BadRequest, "Please pass a Shared Access Signature on the query string or in the request body");
            }

            string sig = req.GetQueryNameValuePairs()
                .FirstOrDefault(q => string.Compare(q.Key, "sig", true) == 0)
                .Value;
            if (sig == null)
            {
                // Get request body
                dynamic data = await req.Content.ReadAsAsync<object>();
                sig = data?.sig;
            }
            if (sig == null)
            {
                log.Info("No sig given");
                return req.CreateResponse(HttpStatusCode.BadRequest, "Please pass a Shared Access Signature on the query string or in the request body");
            }

            string se = req.GetQueryNameValuePairs()
                .FirstOrDefault(q => string.Compare(q.Key, "se", true) == 0)
                .Value;
            if (se == null)
            {
                // Get request body
                dynamic data = await req.Content.ReadAsAsync<object>();
                se = data?.se;
            }
            if (se == null)
            {
                log.Info("No se given");
                return req.CreateResponse(HttpStatusCode.BadRequest, "Please pass a Shared Access Signature on the query string or in the request body");
            }
            
            int intserial = 0;
            if (!int.TryParse(SerialNumber, out intserial))
            {
                log.Info("noninteger SerialNumber");
                return req.CreateResponse(HttpStatusCode.BadRequest, "This is not a number");

            }

            string requestString = "https://" + req.RequestUri.Authority + req.RequestUri.LocalPath;
            log.Info("URL is " + requestString);
            if (!validateSasToken(sr,sig,se, requestString, validationKey, SerialNumber,  log))
            {
                log.Info("Invalid Token");
                return req.CreateResponse(HttpStatusCode.BadRequest, "This is not a valid token");


            }
            log.Info("SAS validation successful!");
            
            //the validation of the serial number happens after the SAS validation so no one can try out valid serial numbers without an SAS
            if( intserial % 7 != 0)
            {
                log.Info("not divisable by 7");
                return req.CreateResponse(HttpStatusCode.BadRequest, "This is not a valid number");

            }
            


            if (null != await rm.GetDeviceAsync(SerialNumber))
            {
                log.Info("Device already created");
                return req.CreateResponse(HttpStatusCode.BadRequest, "This device already exists");

            }
            Device device = new Device(SerialNumber);
            try
            {
                device = await rm.AddDeviceAsync(device);
            } catch (Exception ex )
            {
                log.Info("Create Device Failed");
                return req.CreateResponse(HttpStatusCode.InternalServerError, "Create Device Failed");

            }
            device.Authentication.SymmetricKey.PrimaryKey = CryptoKeyGenerator.GenerateKey(32);
            device.Authentication.SymmetricKey.SecondaryKey = CryptoKeyGenerator.GenerateKey(32);
            try
            {
                await rm.UpdateDeviceAsync(device);
            }
            catch (Exception ex)
            {
                log.Info("Setting Security Information failed");
                return req.CreateResponse(HttpStatusCode.InternalServerError, "Setting Security Information failed");
            }

            StringBuilder deviceConnectionStringBuilder = new StringBuilder();


            var hostName = String.Empty;
            var tokenArray = IoTHubConnectionString.Split(';');
            for (int i = 0; i < tokenArray.Length; i++)
            {
                var keyValueArray = tokenArray[i].Split('=');
                if (keyValueArray[0] == "HostName")
                {
                    hostName = tokenArray[i] + ';';
                    break;
                }
            }

            if (!String.IsNullOrWhiteSpace(hostName))
            {
                deviceConnectionStringBuilder.Append(hostName);
                deviceConnectionStringBuilder.AppendFormat("DeviceId={0}", device.Id);
                deviceConnectionStringBuilder.AppendFormat(";SharedAccessKey={0}", device.Authentication.SymmetricKey.PrimaryKey);
            }
            else
            {
                log.Info("Creating Connection String Failed");
                return req.CreateResponse(HttpStatusCode.InternalServerError, "Creating Connection String failed");
            }

            var deviceConnectionString = deviceConnectionStringBuilder.ToString();
            return req.CreateResponse(HttpStatusCode.OK, deviceConnectionString);
        }

        public static bool validateSasToken(string sr,string sig, string se,string resourceUri, string key, string deviceId, TraceWriter log)
        {

             log.Info("sas parse successful");
             log.Info("sr="+sr);
             log.Info("sig=" + sig);
             log.Info("se=" + se);


            string expiry = se;

            TimeSpan fromEpochStart = DateTime.UtcNow - new DateTime(1970, 1, 1);
            int remainingSeconds = int.Parse(se) - ((int)fromEpochStart.TotalSeconds); 
            if (remainingSeconds<0)
            {
                log.Info("Token already expired:" + remainingSeconds);
                return false;
            }
            else
            {
                log.Info("Token has " + remainingSeconds + "seconds left");
            }

            string stringToSign = WebUtility.UrlEncode(resourceUri) + "\n" + deviceId + "\n" + expiry;

            HMACSHA256 hmac = new HMACSHA256(Convert.FromBase64String(key));
            string signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));

            string token = String.Format(CultureInfo.InvariantCulture, "sr={0}&sig={1}&se={2}", WebUtility.UrlEncode(resourceUri), WebUtility.UrlEncode(signature), expiry);
            string sas = String.Format(CultureInfo.InvariantCulture, "sr={0}&sig={1}&se={2}", WebUtility.UrlEncode(sr),WebUtility.UrlEncode(sig),se);

            if (token == sas) return true;
            log.Info("SAS token validation failed: sent token \"" + sas +"\" is different from computed token \"" + token +"\"");
            return false;
            
        }

    }
}
