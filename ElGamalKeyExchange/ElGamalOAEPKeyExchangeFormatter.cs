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
            // create the instance of the algorithm
            o_algorithm = new ElGamalManaged();
            // init the rnd
            o_random = new Random();
            // init the mask generator
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
            // encure that we are dealing with an ElGamal algorithm
            if (p_key is ElGamal)
            {
                // export the key and push it into the algorithm
                o_algorithm.ImportParameters(((ElGamal)p_key).ExportParameters(false));
            }
            else
            {
                // we can't continue because the algorithm
                // is the one for this class
                throw new ArgumentException("Key Algorithm is not ElGamal", "p_key");
            }
        }

        public override byte[] CreateKeyExchange(byte[] p_byte, Type p_type)
        {
            // the Type parameter is not curently supported by the 
            // .NET Framework, so we just need to work with the byte array
            return CreateKeyExchange(p_byte);
        }

        public override byte[] CreateKeyExchange(byte[] p_byte)
        {
            // create the OAEP padded data
            byte[] x_padded_data = CreateOAEPPaddedData(p_byte);
            // create the ciphertext from the padded data
            byte[] x_ciphertext = o_algorithm.EncryptData(x_padded_data);
            // return the ciphertext
            return x_ciphertext;
        }

        // the lHash value which is the preamble to an OAEP block
        private byte[] o_lhash
          = new BigInteger("da39a3ee5e6b4b0d3255bfef95601890afd80709", 16).getBytes();

        private byte[] CreateOAEPPaddedData(byte[] p_data)
        {
            // create a memory stream to hold the padded data
            MemoryStream x_stream = new MemoryStream();

            // define K
            int x_K = o_algorithm.KeySize / 8 - 1;

            // determine the block size
            int x_max_bytes = x_K - (2 * o_lhash.Length) - 2;
            // determine how many complete blocks there are
            int x_complete_blocks = p_data.Length / x_max_bytes;

            // run through and process the complete blocks
            int i = 0;
            byte[] x_block;
            for (; i < x_complete_blocks; i++)
            {
                x_block = CreateSingleOAEPBlock(p_data, i * x_max_bytes,
                    x_max_bytes, x_K);
                x_stream.Write(x_block, 0, x_block.Length);
            }

            // process any remaining data
            x_block = CreateSingleOAEPBlock(p_data, i * x_max_bytes,
                p_data.Length - (i * x_max_bytes), x_K);
            x_stream.Write(x_block, 0, x_block.Length);

            // return the padded data
            return x_stream.ToArray();
        }

        private byte[] CreateSingleOAEPBlock(byte[] p_data, int p_offset,
            int p_count, int p_K)
        {

            // b.        Generate an octet string PS consisting of
            // k - mLen - 2hLen - 2 zero octets. 
            // The length of PS may be zero.
            byte[] x_PS = new byte[p_K - p_count - (2 * o_lhash.Length) - 2];

            // c.        Concatenate lHash, PS, a single octet with 
            // hexadecimal value 0x01, and the message M to form a data 
            // block DB of length k - hLen - 1 octets as
            // DB = lHash || PS || 0x01 || M . 
            byte[] x_DB = new byte[o_lhash.Length + x_PS.Length + 1 + p_count];
            Array.Copy(o_lhash, 0, x_DB, 0, o_lhash.Length);
            Array.Copy(x_PS, 0, x_DB, o_lhash.Length, x_PS.Length);
            x_DB[o_lhash.Length + x_PS.Length] = 0x01;
            Array.Copy(p_data, p_offset, x_DB,
                o_lhash.Length + x_PS.Length + 1, p_count);

            // d.        Generate a random octet string seed of length hLen
            BigInteger x_temp = new BigInteger();
            x_temp.genRandomBits(o_lhash.Length * 8, o_random);
            byte[] x_seed = x_temp.getBytes();

            // e.        Let dbMask = MGF (seed, k - hLen - 1)
            byte[] x_dbMask = o_mask_generator.GenerateMask(x_seed,
                p_K - o_lhash.Length - 1);

            // f.        Let maskedDB = DB XOR dbMask.
            byte[] x_maskedDB = new byte[x_DB.Length];
            byte[] x_temp_arr =
                (new BigInteger(x_DB) ^ new BigInteger(x_dbMask)).getBytes();
            Array.Copy(x_temp_arr, 0, x_maskedDB,
                x_maskedDB.Length - x_temp_arr.Length, x_temp_arr.Length);

            // g.        Let seedMask = MGF (maskedDB, hLen).
            byte[] x_seedMask = o_mask_generator.GenerateMask(x_maskedDB,
                o_lhash.Length);

            // h.        Let maskedSeed = seed XOR seedMask.
            byte[] x_maskedSeed
                = (new BigInteger(x_seed) ^ new BigInteger(x_seedMask)).getBytes();

            // i. Concatenate a single octet with hexadecimal value 0x00, maskedSeed, 
            // and maskedDB to form an encoded message EM of length k octets as
            // EM = 0x00 || maskedSeed || maskedDB
            byte[] x_EM = new byte[1 + o_lhash.Length + x_DB.Length];
            Array.Copy(x_maskedSeed, 0, x_EM, x_EM.Length - x_DB.Length
                - x_maskedSeed.Length, x_maskedSeed.Length);
            Array.Copy(x_maskedDB, 0, x_EM, x_EM.Length - x_maskedDB.Length,
                x_maskedDB.Length);

            // return the result
            return x_EM;
        }
    }
}
