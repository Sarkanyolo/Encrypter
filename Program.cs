namespace Encrypter
{
    using BotCrypt;
    using System.Text;

    public static class Encrypter
    {
        internal static void Main(string[] args)
        {
            if (args.Length < 2 || args.Length > 3)
            {
                Console.WriteLine("Usage:\nEncrypter filepath password");
                return;
            }

            string path = args[0];
            if (!File.Exists(path))
            {
                Console.WriteLine($"This file is not exists: {path}");
                return;
            }

            var pass = args[1];
            if (pass.Length < 3)
            {
                Console.WriteLine($"This password is too short: {pass}");
                return;
            }

            var content = File.ReadAllBytes(path);
            try
            {
                if (path.EndsWith(".nc"))
                {
                    File.WriteAllBytes(path[0..^3], Decrypt(content, pass));
                }
                else
                {
                    File.WriteAllBytes($"{path}.nc", Encrypt(content, pass));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        private static byte[] Decrypt(byte[] content, string pass)
        {
            return Crypter.DecryptByte(pass, Encoding.UTF8.GetString(content));
        }

        private static byte[] Encrypt(byte[] content, string pass)
        {
            return Encoding.UTF8.GetBytes(Crypter.EncryptByte(pass, content));
        }
    }
}