using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace DemoCifradoRSA
{
    class Program
    {
        public static X509Certificate2 cert = null;

        static void Main(string[] args)
        {
            cert = SelectCertManual();


            string texto = "demostracion de cifrado con llave publica.!!";
            string Texto_Codificado;
            Texto_Codificado = Cifrar(texto);

            Console.WriteLine("Texto tal cual: {0}", texto);
            Console.WriteLine("");
            Console.WriteLine("Texto cifrado: {0}", Texto_Codificado);
            Console.WriteLine("");
            Console.WriteLine("Texto descifrado: {0}", DesCifrar(Texto_Codificado));
            Console.ReadKey();
        }

        /// <summary>
        /// Solo necesita llave publica
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns></returns>
        public static string Cifrar(string plainText)
        {
            RSACryptoServiceProvider publicKey = (RSACryptoServiceProvider)cert.PublicKey.Key;
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] enc = publicKey.Encrypt(plainBytes, false);
            return Convert.ToBase64String(enc);
        }

        /// <summary>
        /// Solo necesita llave privada
        /// </summary>
        /// <param name="encryptedText"></param>
        /// <returns></returns>
        public static string DesCifrar(string encryptedText)
        {
            RSACryptoServiceProvider privateKey = (RSACryptoServiceProvider)cert.PrivateKey;
            byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
            byte[] des = privateKey.Decrypt(encryptedBytes, false);

            return Encoding.UTF8.GetString(des);
        }

        /// <summary>
        /// Metodo encargado de obtener el certificado seleccionado desde el almacen de windows
        /// </summary>
        /// <returns></returns>
        public static X509Certificate2 SelectCertManual()
        {
            try
            {
                //Firmar con selección de certificado en el almacén de certificados de windows
                X509Store store = new X509Store(StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2 cert = null;
                //eligió manualmente el certificado en el almacén
                //Para "X509Certificate2UI" se debe agregar la referencia a "X509Certificate2UI", llamar a "using System.Security;"
                //**X509Certificate2Collection sel = X509Certificate2UI.SelectFromCollection(store.Certificates, null, null, X509SelectionFlag.SingleSelection);                
                X509Certificate2Collection sel = X509Certificate2UI.SelectFromCollection(store.Certificates.Find(X509FindType.FindByKeyUsage, "DigitalSignature", false), null, null, X509SelectionFlag.SingleSelection);
                //X509Certificate2Collection sel = X509Certificate2UI.SelectFromCollection(store.Certificates, null, null, X509SelectionFlag.MultiSelection);
                if (sel.Count > 0)
                    cert = sel[0];
                else
                {
                    //MessageBox.Show("Certificado no Funciona");
                    return null;
                }
                return cert;
            }
            catch (Exception ex)
            {
                throw new Exception("ERROR: " + ex);
            }
        }
    }
}
