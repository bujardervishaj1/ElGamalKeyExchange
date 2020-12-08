using System;
using System.IO;
using System.Security.Cryptography;

namespace ElGamalKeyExchange
{
    public class ElGamalOAEPKeyExchangeFormatter : AsymmetricKeyExchangeFormatter
    {
        private ElGamalManaged o_algorithm;
        private Random o_random;
        private PKCS1MaskGenerationMethod o_mask_generator;
        public ElGamalOAEPKeyExchangeFormatter()
        {
            //krijn instancen e algoritmit
            o_algorithm = new ElGamalManaged();
            //inicializon random
            o_random = new Random();
            //inicializon mask generator 
            o_mask_generator = new PKCS1MaskGenerationMethod();
        }

        public override string Parameters
        {
            get
            {
                return o_algorithm.ToXmlString(false);
            }
        }
        public override void SetKey(AsymmetricAlgorithm p_key)
        {
            //siguron qe kemi te bejme me algoritem ElGamal
            if (p_key is ElGamal)
            {
                o_algorithm.ImportParameters(((ElGamal)p_key).ExportParameters(false));
            }
            else
            {
                throw new ArgumentException("Key Algorithm is not ElGamal", "p_key");
            }
        }

        public override byte[] CreateKeyExchange(byte[] p_byte, Type p_type)
        {
            return CreateKeyExchange(p_byte);
        }

        public override byte[] CreateKeyExchange(byte[] p_byte)
        {
            byte[] x_padded_data = CreateOAEPPaddedData(p_byte);
            byte[] x_ciphertext = o_algorithm.EncryptData(x_padded_data);
            return x_ciphertext;
        }

        private byte[] o_lhash
          = new BigInteger("da39a3ee5e6b4b0d3255bfef95601890afd80709", 16).getBytes();

        //krijon nje memory stream  per te mbajtur te padded data
        private byte[] CreateOAEPPaddedData(byte[] p_data)
        {
            MemoryStream x_stream = new MemoryStream();
            
            // definon K
            int x_K = o_algorithm.KeySize / 8 - 1;

            //percaktoni madhesine e bllokut
            int x_max_bytes = x_K - (2 * o_lhash.Length) - 2;

            //percakton se sa blloqe te plota jane
            int x_complete_blocks = p_data.Length / x_max_bytes;
            
            //ekzekuton dhe perpunon blloqet e plota
            int i = 0;
            byte[] x_block;
            for (; i < x_complete_blocks; i++)
            {
                x_block = CreateSingleOAEPBlock(p_data, i * x_max_bytes,
                    x_max_bytes, x_K);
                x_stream.Write(x_block, 0, x_block.Length);
            }

            // perpunon qdo te dhene te mbetur
            x_block = CreateSingleOAEPBlock(p_data, i * x_max_bytes,
                p_data.Length - (i * x_max_bytes), x_K);
            x_stream.Write(x_block, 0, x_block.Length);

            return x_stream.ToArray();
        }

        private byte[] CreateSingleOAEPBlock(byte[] p_data, int p_offset,
            int p_count, int p_K)
        {

            byte[] x_PS = new byte[p_K - p_count - (2 * o_lhash.Length) - 2];

            byte[] x_DB = new byte[o_lhash.Length + x_PS.Length + 1 + p_count];
            Array.Copy(o_lhash, 0, x_DB, 0, o_lhash.Length);
            Array.Copy(x_PS, 0, x_DB, o_lhash.Length, x_PS.Length);
            x_DB[o_lhash.Length + x_PS.Length] = 0x01;
            Array.Copy(p_data, p_offset, x_DB,
                o_lhash.Length + x_PS.Length + 1, p_count);

            BigInteger x_temp = new BigInteger();
            x_temp.genRandomBits(o_lhash.Length * 8, o_random);
            byte[] x_seed = x_temp.getBytes();

            byte[] x_dbMask = o_mask_generator.GenerateMask(x_seed,
                p_K - o_lhash.Length - 1);

            byte[] x_maskedDB = new byte[x_DB.Length];
            byte[] x_temp_arr =
                (new BigInteger(x_DB) ^ new BigInteger(x_dbMask)).getBytes();
            Array.Copy(x_temp_arr, 0, x_maskedDB,
                x_maskedDB.Length - x_temp_arr.Length, x_temp_arr.Length);

            byte[] x_seedMask = o_mask_generator.GenerateMask(x_maskedDB,
                o_lhash.Length);

            byte[] x_maskedSeed
                = (new BigInteger(x_seed) ^ new BigInteger(x_seedMask)).getBytes();

            byte[] x_EM = new byte[1 + o_lhash.Length + x_DB.Length];
            Array.Copy(x_maskedSeed, 0, x_EM, x_EM.Length - x_DB.Length
                - x_maskedSeed.Length, x_maskedSeed.Length);
            Array.Copy(x_maskedDB, 0, x_EM, x_EM.Length - x_maskedDB.Length,
                x_maskedDB.Length);

            return x_EM;
        }
    }
}
