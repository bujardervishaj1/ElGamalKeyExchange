using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace ElGamalKeyExchange
{
    public class ElGamalManaged : ElGamal
    {
        private ElGamalKeyStruct o_key_struct;
        public ElGamalManaged()
        {
            o_key_struct = new ElGamalKeyStruct();
            o_key_struct.P = new BigInteger(0);
            o_key_struct.G = new BigInteger(0);
            o_key_struct.Y = new BigInteger(0);
            o_key_struct.X = new BigInteger(0);
            KeySizeValue = 1024;
            LegalKeySizesValue = new KeySizes[] { new KeySizes(384, 1088, 8) };
        }
        public override string SignatureAlgorithm
        {
            get
            {
                return "ElGamal";
            }
        }

        public override string KeyExchangeAlgorithm
        {
            get
            {
                return "ElGamal";
            }
        }

        private void CreateKeyPair(int p_key_strength)
        {
            Random x_random_generator = new Random();

            o_key_struct.P = BigInteger.genPseudoPrime(p_key_strength,
                16, x_random_generator);

            o_key_struct.X = new BigInteger();
            o_key_struct.X.genRandomBits(p_key_strength - 1, x_random_generator);
            o_key_struct.G = new BigInteger();
            o_key_struct.G.genRandomBits(p_key_strength - 1, x_random_generator);

            o_key_struct.Y = o_key_struct.G.modPow(o_key_struct.X, o_key_struct.P);
        }

        private bool NeedToGenerateKey()
        {
            return o_key_struct.P == 0 && o_key_struct.G == 0 && o_key_struct.Y == 0;
        }

        public ElGamalKeyStruct KeyStruct
        {
            get
            {
                if (NeedToGenerateKey())
                {
                    CreateKeyPair(KeySizeValue);
                }
                return o_key_struct;
            }
            set
            {
                o_key_struct = value;
            }
        }

        public override void ImportParameters(ElGamalParameters p_parameters)
        {
            o_key_struct.P = new BigInteger(p_parameters.P);
            o_key_struct.G = new BigInteger(p_parameters.G);
            o_key_struct.Y = new BigInteger(p_parameters.Y);
            if (p_parameters.X != null && p_parameters.X.Length > 0)
            {
                o_key_struct.X = new BigInteger(p_parameters.X);
            }
            KeySizeValue = o_key_struct.P.bitCount();
        }

        public override ElGamalParameters ExportParameters(bool
        p_include_private_params)
        {
            if (NeedToGenerateKey())
            {
                CreateKeyPair(KeySizeValue);
            }

            ElGamalParameters x_params = new ElGamalParameters();
            x_params.P = o_key_struct.P.getBytes();
            x_params.G = o_key_struct.G.getBytes();
            x_params.Y = o_key_struct.Y.getBytes();

            if (p_include_private_params)
            {
                x_params.X = o_key_struct.X.getBytes();
            }
            else
            {
                x_params.X = new byte[1];
            }
            return x_params;
        }

        public override byte[] EncryptData(byte[] p_data)
        {
            if (NeedToGenerateKey())
            {
                CreateKeyPair(KeySizeValue);
            }
            ElGamalEncryptor x_enc = new ElGamalEncryptor(o_key_struct);
            return x_enc.ProcessData(p_data);
        }

        public override byte[] DecryptData(byte[] p_data)
        {
            if (NeedToGenerateKey())
            {
                CreateKeyPair(KeySizeValue);
            }
            ElGamalDecryptor x_enc = new ElGamalDecryptor(o_key_struct);
            return x_enc.ProcessData(p_data);
        }
        protected override void Dispose(bool p_bool)
        {
        }

        public override byte[] Sign(byte[] p_hashcode)
        {
            throw new System.NotImplementedException();
        }

        public override bool VerifySignature(byte[] p_hashcode, byte[] p_signature)
        {
            throw new System.NotImplementedException();
        }
    }
}
