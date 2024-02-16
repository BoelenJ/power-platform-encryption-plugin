using System;
using Microsoft.Xrm.Sdk;
using System.Security.Cryptography;
using System.IO;
using Microsoft.Xrm.Sdk.Query;


namespace Encryption
{
    public class Decrypt : IPlugin
    {
        public void Execute(IServiceProvider serviceProvider)
        {
            // Get the execution context.
            IPluginExecutionContext context = (IPluginExecutionContext) serviceProvider.GetService(typeof(IPluginExecutionContext));
            IOrganizationServiceFactory serviceFactory = (IOrganizationServiceFactory)serviceProvider.GetService(typeof(IOrganizationServiceFactory));
            IOrganizationService service = serviceFactory.CreateOrganizationService(context.UserId);

            // Grab the input variables.
            string inputString = (string)context.InputParameters["EncryptedString"];
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
                returnValue = DecryptString(inputString, key);
            }
            catch(Exception ex)
            {
                throw new InvalidPluginExecutionException("An error occurred while encrypting. ", ex);

            }

            // Return encrypted value.
            context.OutputParameters["DecryptedString"] = returnValue;
        }

        static string DecryptString(string encryptedText, byte[] Key)
        {
            // Check arguments.
            if (encryptedText == null || encryptedText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");

            string plaintext = null;
            
            // Get all bytes
            var allBytes = Convert.FromBase64String(encryptedText);

            using (Aes aesAlg = Aes.Create())
            {
                // Get the IV based on the encrypted text (pre-pended to the data)
                byte[] iv = new byte[aesAlg.BlockSize / 8];
                if (allBytes.Length < iv.Length) throw new ArgumentException("Message was less than IV size.");

                Array.Copy(allBytes, iv, iv.Length);
                // get the data we need to decrypt
                byte[] cipherBytes = new byte[allBytes.Length - iv.Length];
                Array.Copy(allBytes, iv.Length, cipherBytes, 0, cipherBytes.Length);

                // Create a decrytor to perform the stream transform.
                var decryptor = aesAlg.CreateDecryptor(Key, iv);

                // Create the streams used for decryption. 
                using (MemoryStream msDecrypt = new MemoryStream(cipherBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream 
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
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
