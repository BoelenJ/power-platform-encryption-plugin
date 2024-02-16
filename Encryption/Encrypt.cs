using System;
using Microsoft.Xrm.Sdk;
using System.Security.Cryptography;
using System.IO;
using Microsoft.Xrm.Sdk.Query;

namespace Encryption
{
    public class Encrypt : IPlugin
    {
        public void Execute(IServiceProvider serviceProvider)
        {
            // Get the execution context.
            IPluginExecutionContext context = (IPluginExecutionContext) serviceProvider.GetService(typeof(IPluginExecutionContext));
            IOrganizationServiceFactory serviceFactory = (IOrganizationServiceFactory)serviceProvider.GetService(typeof(IOrganizationServiceFactory));
            IOrganizationService service = serviceFactory.CreateOrganizationService(context.UserId);
  
            // Grab the input variables.
            string inputString = (string)context.InputParameters["InputString"];
            string encryptionKey = (string)context.InputParameters["EncryptionKey"];
            bool useEnvironmentVariable = (bool)context.InputParameters["UseEnvironmentVariable"];
            if (useEnvironmentVariable)
            {
                try
                {
                    string value = GetEnvironmentVariable(service, encryptionKey);
                    encryptionKey = value;
                }
                catch (Exception ex)
                {
                    throw new InvalidPluginExecutionException("Unable to get value from the environment variable.", ex);

                }

            }
            

            if (encryptionKey.Length != 32)
            {
                throw new InvalidPluginExecutionException("The encryption key needs to be 32 characters long");
            }

            // Encryption logic.
            string returnValue;

            try
            {
                var key = Convert.FromBase64String(encryptionKey);
                returnValue = EncryptString(inputString, key);
            }
            catch(Exception ex)
            {
                throw new InvalidPluginExecutionException("An error occurred while encrypting. ", ex);

            }

            // Return encrypted value.
            context.OutputParameters["EncryptedString"] = returnValue;
        }

        static string EncryptString(string plainText, byte[] Key)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");

            byte[] returnvalue;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.GenerateIV();

                var iv = aesAlg.IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        var encrypted = msEncrypt.ToArray();
                        returnvalue = new byte[encrypted.Length + iv.Length];
                        // append our IV so our decrypt can get it
                        Array.Copy(iv, returnvalue, iv.Length);
                        // append our encrypted data
                        Array.Copy(encrypted, 0, returnvalue, iv.Length, encrypted.Length);
                    }
                }
            }

            return Convert.ToBase64String(returnvalue);
        }

        private string GetEnvironmentVariable(IOrganizationService service, string envVariableName)
        {

            string fetchXml;
            EntityCollection result;
            string envVariableValue = string.Empty;

            fetchXml = String.Format(@"<fetch version=""1.0"" output-format=""xml-platform"" mapping=""logical"" distinct=""false"">
            <entity name=""environmentvariablevalue"">
            <attribute name=""environmentvariablevalueid"" />
            <attribute name=""value"" />
            <link-entity name=""environmentvariabledefinition"" from=""environmentvariabledefinitionid"" to=""environmentvariabledefinitionid"" link-type=""inner"">
                <attribute name=""schemaname"" />
                <filter type=""and"">
                <condition attribute=""schemaname"" operator=""eq"" value=""{0}"" />
                </filter>
            </link-entity>
            </entity>
        </fetch>", envVariableName);

            result = service.RetrieveMultiple(new FetchExpression(fetchXml));

            if (result != null && result.Entities.Count > 0)
            {
                envVariableValue = result.Entities[0].GetAttributeValue<string>("value");
            }

            return envVariableValue;

        }
    }


}
