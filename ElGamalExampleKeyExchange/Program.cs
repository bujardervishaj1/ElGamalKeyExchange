﻿using ElGamalKeyExchange;
using System;
using System.Security.Cryptography;

namespace ElGamalExampleKeyExchange
{
    class Program
    {
        static void Main(string[] args)
        {
            //krijon nje instaance te algoritmit Rijndael dhe
            //specifikon 128bit si gjatesine e celesit

            Rijndael x_rijndael = Rijndael.Create();
            x_rijndael.KeySize = 128;

            // klasa do te krijoje nje qeles te ri per te marre vleren e sesionit
            byte[] x_session_key = x_rijndael.Key;

            Console.WriteLine("Session key generated: ");
            foreach (var b in x_session_key)
            {
                Console.Write("{0:X2} ", b);
            }

            //krijon nje instance te ElGamal
            var x_elgamal = new ElGamalManaged();

            ElGamalOAEPKeyExchangeFormatter x_formatter = new ElGamalOAEPKeyExchangeFormatter();

            //instancen kemi krijuar per te perdorur kur enkripton te dhenat kryesore te sesionit
            x_formatter.SetKey(x_elgamal);


            //enkriptoni celesin e sesionit me formater
            byte[] x_exchange_data = x_formatter.CreateKeyExchange(x_session_key);

            Console.WriteLine("\nData to be exchanged: ");
            //shkruan te dhenat e enkriptuara
            foreach (byte b in x_exchange_data)
            {
                Console.Write("{0:X2} ", b);
            }

            ElGamalOAEPKeyExchangeDeformatter x_deformatter = new ElGamalOAEPKeyExchangeDeformatter();
            x_deformatter.SetKey(x_elgamal);

            byte[] x_session_key_deformatted = x_deformatter.DecryptKeyExchange(x_exchange_data);
            Console.WriteLine("\nSession key retrived: ");
            foreach (var b in x_session_key_deformatted)
            {
                Console.Write("{0:X2} ", b);
            }

            if (x_session_key.Length == x_session_key_deformatted.Length)
            {
                for (int i = 0; i < x_session_key.Length; i++)
                {
                    if (x_session_key[i] != x_session_key_deformatted[i])
                    {
                        Console.WriteLine("\nSession key generated and session key retrived from deformatter is not the same!!");
                        return;
                    }
                }

                Console.WriteLine("\nSession key generated and session key retrived from deformatter is the same.");
            }
        }
    }
}
