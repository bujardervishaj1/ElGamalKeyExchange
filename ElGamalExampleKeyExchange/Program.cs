using ElGamalKeyExchange;
using System;
using System.Security.Cryptography;

namespace ElGamalExampleKeyExchange
{
    class Program
    {
        static void Main(string[] args)
        {
            Rijndael x_rijndael = Rijndael.Create();
            x_rijndael.KeySize = 128;

            byte[] x_session_key = x_rijndael.Key;

            var x_elgamal = new ElGamalManaged();


            ElGamalOAEPKeyExchangeFormatter x_formatter = new ElGamalOAEPKeyExchangeFormatter();

            x_formatter.SetKey(x_elgamal);

            byte[] x_exchange_data = x_formatter.CreateKeyExchange(x_session_key);

            foreach (byte b in x_exchange_data)
            {
                Console.Write("{0:X2} ", b);
            }

            ElGamalOAEPKeyExchangeDeformatter x_deformatter = new ElGamalOAEPKeyExchangeDeformatter();
            x_deformatter.SetKey(x_elgamal);

            byte[] x_session_key_deformatted = x_deformatter.DecryptKeyExchange(x_exchange_data);
        }
    }
}
