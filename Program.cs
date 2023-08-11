using System.Text;

namespace AsymmetriskKrypteringsOpg
{
    internal class Program
    {
        static void Main(string[] args)
        {
            //Create a new instance of RSAParameterKey calss
            var rsaParameters = new RSAParameterKey();

            string testText = "En meget hemmelig tekst, der ikke må læses af andre";

            try
            {
                rsaParameters.AssingningNewKey();

                var rsaEncrypted = rsaParameters.Encrypt(Encoding.UTF8.GetBytes(testText));
                var rsaDecrypted = rsaParameters.Decrypt(rsaEncrypted);

                var rsaDecryptedText = Encoding.UTF8.GetString(rsaDecrypted); 

                Console.WriteLine("RSA parameter");
                Console.WriteLine();

                foreach (var item in rsaParameters.privateKey.GetType().GetFields())
                {
                    byte[] value = (byte[])item.GetValue(rsaParameters.privateKey);
                    Console.WriteLine($"{item.Name}: \n{BitConverter.ToString(value)}");
                }

                Console.WriteLine();
                Console.WriteLine("Første tekst: \r\n" + testText);
                Console.WriteLine();
                Console.WriteLine("Kryptered tekst: \r\n" + Convert.ToBase64String(rsaEncrypted));
                Console.WriteLine();
                Console.WriteLine("Dekryptered tekst: \r\n" + rsaDecryptedText);
            }
            catch (ArgumentNullException)
            {
                Console.WriteLine("Der skete den fejl!"); 
            }
        }
    }
}