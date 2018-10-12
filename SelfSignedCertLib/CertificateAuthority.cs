using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using SelfSignedCertLib.Serialization;

namespace SelfSignedCertLib
{
    /// <summary>
    /// Cert Authority
    /// </summary>
    public sealed class CertificateAuthority : CertificateBase
    {
        /// <summary>
        /// our signature alg
        /// </summary>
        public static readonly string SignatureAlg = "SHA256WithRSA";

        /// <summary>
        /// subj name
        /// </summary>
        public string SubjectName { get; }

        /// <summary>
        /// RSA key size; 2048 is a good default
        /// </summary>
        public int KeySize { get; }

        /// <summary>
        /// public key access
        /// </summary>
        public X509Certificate2 PublicKey { get;  }

        /// <summary>
        /// private key storage
        /// </summary>
        /// <remarks>
        /// in this lib we don't expose bouncycastle types as public.
        /// </remarks>
        internal AsymmetricKeyParameter PrivateKeyBouncy { get; }

        /// <summary>
        /// create a brand new certificate authority
        /// </summary>
        /// <param name="subjectName">subject name ex. "CN=Something"</param>
        /// <param name="keySize">RSA key strength; 2048 is a good default</param>
        /// <param name="lifespan">validity period</param>
        public CertificateAuthority(string subjectName, int keySize = 2048, TimeSpan? lifespan = null)
        {
            //default validity about two years
            var life = lifespan.GetValueOrDefault(TimeSpan.FromDays(365 * 2));

            //store facts
            SubjectName = subjectName;
            KeySize = keySize;

            (PrivateKeyBouncy, PublicKey) = GenerateCACertificate(SubjectName, KeySize, life);

            //doublecheck we stored the right certs in the right places
            if (PublicKey.HasPrivateKey)
            {
                throw new InvalidOperationException("runtime assert: Wasn't expecting PublicKey to have private material");
            }
        }

        /// <summary>
        /// gen ca cert
        /// </summary>
        /// <param name="subjectName"></param>
        /// <param name="keyStrength"></param>
        /// <returns>bouncy private, dotnet public</returns>
        /// <remarks>
        /// Many thanks to this stackoverflow post:
        /// https://stackoverflow.com/a/22237794
        /// </remarks>
        private (AsymmetricKeyParameter, X509Certificate2) GenerateCACertificate(string subjectName, int keyStrength, TimeSpan lifespan)
        {
            // Generating Random Numbers
            var random = _rand;

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            certificateGenerator.SetSerialNumber(GenerateSerial());

            // Issuer and Subject Name
            var subjectDN = new X509Name(subjectName);
            var issuerDN = subjectDN;
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            //for good measure let's include key usage
            certificateGenerator.AddExtension("2.5.29.15",
                false,
                new X509KeyUsage(X509KeyUsage.KeyCertSign | X509KeyUsage.DigitalSignature | X509KeyUsage.CrlSign));

            //set validity
            AssignLife(certificateGenerator, lifespan);

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Generating the Certificate
            var issuerKeyPair = subjectKeyPair;

            // selfsign certificate
            var signatureFactory = new Asn1SignatureFactory(SignatureAlg, issuerKeyPair.Private, random);
            var certificate = certificateGenerator.Generate(signatureFactory);
            //var x509 = new X509Certificate2(certificate.GetEncoded(), (string)null);
            
            var cerr = DotNetUtilities.ToX509Certificate(certificate);
            var buf = cerr.Export(X509ContentType.Cert);  //<-- .Cert is the magic option for Public Only export
            var pubonly = new X509Certificate2(buf);
            if (pubonly.HasPrivateKey)
            {
                throw new InvalidOperationException("wasn't expecting a privkey");  //never happens.
            }

            return (issuerKeyPair.Private, pubonly);
        }

        /// <summary>
        /// serial prelude for CA
        /// </summary>
        /// <returns>0x0100</returns>
        internal override IEnumerable<byte> GetSerialPrelude()
        {
            return new byte[] { 0x01, 0x00 };
        }


        #region XML Serialization
        /// <summary>
        /// build from xml serial struct
        /// </summary>
        /// <param name="xel"></param>
        private CertificateAuthority(CertificateAuthorityForEphemeralCertsXml xel)
        {
            SubjectName = xel.SubjectName;
            PrivateKeyBouncy = DotNetUtilities.GetRsaKeyPair(xel.PrivateKeyParameters).Private;
            var cert = new X509Certificate2(xel.PublicKeyData);

            PublicKey = cert;
            KeySize = cert.PublicKey.Key.KeySize;

            if (SubjectName != cert.SubjectName.Name)
            {
                throw new InvalidOperationException($"xml CA invalid: expecting subject {cert.SubjectName.Name}");
            }
            if (xel.Thumbprint != cert.Thumbprint)
            {
                throw new InvalidOperationException($"xml CA invalid: expecting Thumbprint {cert.Thumbprint}");
            }
            if (xel.SerialNumber != cert.SerialNumber)
            {
                throw new InvalidOperationException($"xml CA invalid: expecting Serial {cert.SerialNumber}");
            }
        }

        /// <summary>
        /// Cons, given xml string
        /// </summary>
        /// <param name="xmlstring">xml string that was pulled via ToXml</param>
        /// <returns></returns>
        public static CertificateAuthority FromXmlString(string xmlstring)
        {
            return new CertificateAuthority(Deser(xmlstring));
        }

        /// <summary>
        /// export to proprietary xml format
        /// </summary>
        /// <returns>public key and private key in proprietary xml form, plus with some attributes redundantly expressed in the XML</returns>
        public string ToXml()
        {
            var toser = new CertificateAuthorityForEphemeralCertsXml
            {
                SerialNumber = PublicKey.SerialNumber,
                SubjectName = PublicKey.SubjectName.Name,
                Expires = PublicKey.GetExpirationDateString(),
                Thumbprint = PublicKey.Thumbprint,

                PrivateKeyParameters = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)PrivateKeyBouncy),
                PublicKeyData = PublicKey.Export(X509ContentType.Cert)
            };

            var sb = new StringBuilder();
            using (var sw = new StringWriter(sb))
            {
                var xser = new XmlSerializer(typeof(CertificateAuthorityForEphemeralCertsXml));
                xser.Serialize(sw, toser);
                return sb.ToString();
            }
        }

        /// <summary>
        /// deser helper
        /// </summary>
        /// <param name="xmlstring"></param>
        /// <returns></returns>
        private static CertificateAuthorityForEphemeralCertsXml Deser(string xmlstring)
        {
            var xser = new XmlSerializer(typeof(CertificateAuthorityForEphemeralCertsXml));
            using (var sr = new StringReader(xmlstring))
            {
                return (CertificateAuthorityForEphemeralCertsXml)xser.Deserialize(sr);
            }

        }
        #endregion

    }
}
