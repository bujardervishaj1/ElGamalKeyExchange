using System;
using System.IO;
using System.Security.Cryptography;

namespace ElGamalKeyExchange
{
    public class ElGamalOAEPKeyExchangeDeformatter : AsymmetricKeyExchangeDeformatter
    {
        private ElGamalManaged o_algorithm;
        private PKCS1MaskGenerationMethod o_mask_generator;

        public ElGamalOAEPKeyExchangeDeformatter()
        {
            o_algorithm = new ElGamalManaged();
            o_mask_generator = new PKCS1MaskGenerationMethod();
        }

        public override void SetKey(AsymmetricAlgorithm p_key)
        {
            if (p_key is ElGamal)
            {
                o_algorithm.ImportParameters(((ElGamal)p_key).ExportParameters(true));
            }
            else
            {
                throw new ArgumentException("Key Algorithm is not ElGamal", "p_key");
            }
        }
        public override string Parameters
        {
            get
            {
                return o_algorithm.ToXmlString(true);
            }
            set
            {
                o_algorithm.FromXmlString(value);
            }
        }

        public override byte[] DecryptKeyExchange(byte[] p_byte)
        {
            byte[] x_padded = o_algorithm.DecryptData(p_byte);
            byte[] x_plaintext = RestoreOAEPPaddedData(x_padded);
            return x_plaintext;
        }

        private byte[] o_lhash
          = new BigInteger("da39a3ee5e6b4b0d3255bfef95601890afd80709", 16).getBytes();

        private byte[] RestoreOAEPPaddedData(byte[] p_data)
        {
            // create a memory stream to hold the padded data
            MemoryStream x_stream = new MemoryStream();

            // define K
            int x_K = o_algorithm.KeySize / 8 - 1;

            // determine how many complete blocks there are
            int x_blocks = p_data.Length / x_K;

            // run through and process the blocks blocks
            byte[] x_block;
            for (int i = 0; i < x_blocks; i++)
            {
                x_block = RestoreSingleOAEPBlock(p_data, i * x_K, x_K, x_K);
                x_stream.Write(x_block, 0, x_block.Length);
            }

            // return the padded data
            return x_stream.ToArray();
        }

        private byte[] RestoreSingleOAEPBlock(byte[] p_data, int p_offset,
            int p_count, int p_K)
        {

            // b. Separate the encoded message EM into a single octet Y, 
            // an octet string maskedSeed of length hLen, and an octet 
            // string maskedDB of length k - hLen - 1 
            // as EM = Y || maskedSeed || maskedDB
            byte[] x_maskedSeed = new byte[o_lhash.Length];
            Array.Copy(p_data, p_offset + 1, x_maskedSeed, 0, o_lhash.Length);
            byte[] x_maskedDB = new byte[p_K - o_lhash.Length - 1];
            Array.Copy(p_data, p_offset + 1 + o_lhash.Length, x_maskedDB,
                0, x_maskedDB.Length);

            // c.        Let seedMask = MGF (maskedDB, hLen).
            byte[] x_seedMask
                = o_mask_generator.GenerateMask(x_maskedDB, o_lhash.Length);

            // d.        Let seed = maskedSeed XOR seedMask
            byte[] x_seed = (new BigInteger(x_maskedSeed)
                ^ new BigInteger(x_seedMask)).getBytes();

            // e.        Let dbMask = MGF (seed, k - hLen - 1).
            byte[] x_dbMask
                = o_mask_generator.GenerateMask(x_seed, p_K - o_lhash.Length - 1);

            // f.        Let DB = maskedDB XOR dbMask.
            byte[] x_DB = (new BigInteger(x_maskedDB)
                ^ new BigInteger(x_dbMask)).getBytes();

            // g.        Separate DB into an octet string lHash' of length hLen, a 
            // (possibly empty) padding string PS consisting of octets with 
            // hexadecimal value 0x00, and a message M as 
            // DB = lHash' || PS || 0x01 || M .
            // If there is no octet with hexadecimal value 0x01 to separate PS from M, 
            // if lHash does not equal lHash', or if Y is nonzero, 
            // output "decryption error" and stop. 
            for (int i = 0; i < o_lhash.Length; i++)
            {
                if (x_DB[i] != o_lhash[i])
                {
                    throw new CryptographicException("Decryption Error");
                }
            }
            if (p_data[0] != 0)
            {
                throw new CryptographicException("Decryption Error");
            }
            // find the index representing the start of M
            int x_index = -1;
            for (int i = o_lhash.Length; i < x_DB.Length; i++)
            {
                if (x_DB[i] == 0x01)
                {
                    // the next index is the start of M
                    x_index = i + 1;
                    break;
                }
                else if (x_DB[i] != (byte)0x00)
                {
                    throw new CryptographicException("Decryption Error");
                }
            }
            if (x_index == -1)
            {
                throw new CryptographicException("Decryption Error");
            }

            // extract and return M
            byte[] x_message = new byte[x_DB.Length - x_index];
            Array.Copy(x_DB, x_index, x_message, 0, x_message.Length);
            return x_message;
        }

    }
}
