using System;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace ElGamalKeyExchange
{
    public abstract class ElGamal : AsymmetricAlgorithm
    {
        public abstract void ImportParameters(ElGamalParameters p_parameters);
        public abstract ElGamalParameters ExportParameters(bool
            p_include_private_params);

        public abstract byte[] EncryptData(byte[] p_data);
        public abstract byte[] DecryptData(byte[] p_data);
        public abstract byte[] Sign(byte[] p_hashcode);
        public abstract bool VerifySignature(byte[] p_hashcode, byte[] p_signature);

        public override string ToXmlString(bool p_include_private)
        {
            ElGamalParameters x_params = ExportParameters(p_include_private);

            StringBuilder x_sb = new StringBuilder();
            
            x_sb.Append("<ElGamalKeyValue>");
            
            x_sb.Append("<P>" + Convert.ToBase64String(x_params.P) + "</P>");
            x_sb.Append("<G>" + Convert.ToBase64String(x_params.G) + "</G>");
            x_sb.Append("<Y>" + Convert.ToBase64String(x_params.Y) + "</Y>");
            if (p_include_private)
            {
                x_sb.Append("<X>" + Convert.ToBase64String(x_params.X) + "</X>");
            }
            
            x_sb.Append("</ElGamalKeyValue>");
            return x_sb.ToString();
        }

        public override void FromXmlString(String p_string)
        {
            ElGamalParameters x_params = new ElGamalParameters();
         
            XmlTextReader x_reader =
                new XmlTextReader(new System.IO.StringReader(p_string));

            while (x_reader.Read())
            {
                if (true || x_reader.IsStartElement())
                {
                    switch (x_reader.Name)
                    {
                        case "P":
                            x_params.P =
                                Convert.FromBase64String(x_reader.ReadString());
                            break;
                        case "G":
                            x_params.G =
                                Convert.FromBase64String(x_reader.ReadString());
                            break;
                        case "Y":
                            x_params.Y =
                                Convert.FromBase64String(x_reader.ReadString());
                            break;
                        case "X":
                            x_params.X =
                                Convert.FromBase64String(x_reader.ReadString());
                            break;
                    }
                }
            }

            ImportParameters(x_params);
        }
    }
}
