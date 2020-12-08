using System;
using System.IO;

namespace ElGamalKeyExchange
{
    public abstract class ElGamalAbstractCipher
    {
        protected int o_block_size;
        protected int o_plaintext_blocksize;
        protected int o_ciphertext_blocksize;
        protected ElGamalKeyStruct o_key_struct;

        public ElGamalAbstractCipher(ElGamalKeyStruct p_key_struct)
        {
            o_key_struct = p_key_struct;

            o_plaintext_blocksize = (p_key_struct.P.bitCount() - 1) / 8;
            o_ciphertext_blocksize = ((p_key_struct.P.bitCount() + 7) / 8) * 2;

            o_block_size = o_plaintext_blocksize;
        }

        public byte[] ProcessData(byte[] p_data)
        {
            MemoryStream x_stream = new MemoryStream();

            int x_complete_blocks = p_data.Length / o_block_size;

            byte[] x_block = new Byte[o_block_size];

            int i = 0;
            for (; i < x_complete_blocks; i++)
            {
                Array.Copy(p_data, i * o_block_size, x_block, 0, o_block_size);
                byte[] x_result = ProcessDataBlock(x_block);
                x_stream.Write(x_result, 0, x_result.Length);
            }

            byte[] x_final_block = new Byte[p_data.Length -
                (x_complete_blocks * o_block_size)];
            Array.Copy(p_data, i * o_block_size, x_final_block, 0,
                x_final_block.Length);

            byte[] x_final_result = ProcessFinalDataBlock(x_final_block);

            x_stream.Write(x_final_result, 0, x_final_result.Length);

            return x_stream.ToArray();
        }

        protected abstract byte[] ProcessDataBlock(byte[] p_block);

        protected abstract byte[] ProcessFinalDataBlock(byte[] p_final_block);
    }
}
