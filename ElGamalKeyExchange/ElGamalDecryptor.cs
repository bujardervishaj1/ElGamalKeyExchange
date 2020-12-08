using System;

namespace ElGamalKeyExchange
{
    public class ElGamalDecryptor : ElGamalAbstractCipher
    {

        public ElGamalDecryptor(ElGamalKeyStruct p_struct) : base(p_struct)
        {
            o_block_size = o_ciphertext_blocksize;
        }

        protected override byte[] ProcessDataBlock(byte[] p_block)
        {
            byte[] x_a_bytes = new byte[o_ciphertext_blocksize / 2];
            Array.Copy(p_block, 0, x_a_bytes, 0, x_a_bytes.Length);
            byte[] x_b_bytes = new Byte[o_ciphertext_blocksize / 2];
            Array.Copy(p_block, x_a_bytes.Length, x_b_bytes, 0, x_b_bytes.Length);
            BigInteger A = new BigInteger(x_a_bytes);
            BigInteger B = new BigInteger(x_b_bytes);
            BigInteger M = (B *
                A.modPow(o_key_struct.X, o_key_struct.P).modInverse(o_key_struct.P))
                % o_key_struct.P;
            byte[] x_m_bytes = M.getBytes();
            if (x_m_bytes.Length < o_plaintext_blocksize)
            {
                byte[] x_full_result = new byte[o_plaintext_blocksize];
                Array.Copy(x_m_bytes, 0, x_full_result,
                    o_plaintext_blocksize - x_m_bytes.Length, x_m_bytes.Length);
                x_m_bytes = x_full_result;
            }
            return x_m_bytes;
        }
        protected override byte[] ProcessFinalDataBlock(byte[] p_final_block)
        {
            if (p_final_block.Length > 0)
            {
                return ProcessDataBlock(p_final_block);
            }
            else
            {
                return new byte[0];
            }
        }
    }
}
