using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

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

namespace SelfSignedCertLib
{
    /// <summary>
    /// certificate maker
    /// </summary>
    /// <remarks>
    /// Many thanks to this stackoverflow post:
    /// https://stackoverflow.com/a/22237794
    /// </remarks>
    public sealed class Certificate : CertificateBase
    {
        /// <summary>
        /// our newly minted certificate.
        /// </summary>
        public X509Certificate2 Cert { get; }

        /// <summary>
        /// access to authority that was passed in cons
        /// </summary>
        public CertificateAuthority Authority { get; }

        /// <summary>
        /// mint a new certificate
        /// it will be available via Cert property
        /// </summary>
        /// <param name="ca">CA; its subject name will be used as issuer name</param>
        /// <param name="subjectName">subj name of the certificate being minted. A useful value is: "CN=localhost"</param>
        /// <param name="keySize">key size; if zero or negative, we'll actually just use the key size of the CA</param>
        /// <param name="lifespan">life span</param>
        /// <remarks>
        /// for simplicity's sake we'll default to the ca key strength as the cert key strength
        /// </remarks>
        public Certificate(CertificateAuthority ca, string subjectName, int keySize = 0, TimeSpan? lifespan = null)
        {
            //default key size is just match CA
            if (keySize <= 0)
            {
                keySize = ca.KeySize;
            }

            //default validity about two years
            var life = lifespan.GetValueOrDefault(TimeSpan.FromDays(365 * 2));

            Authority = ca;
            Cert = GenerateSelfSignedCertificate(subjectName, ca.SubjectName, ca.PrivateKeyBouncy, keySize, life);
        }

        /// <summary>
        /// gen cert
        /// </summary>
        /// <param name="subjectName"></param>
        /// <param name="issuerName"></param>
        /// <param name="issuerPrivKey"></param>
        /// <param name="keyStrength"></param>
        /// <returns>.net framewory style cert</returns>
        /// <remarks>
        /// Many thanks to this stackoverflow post:
        /// https://stackoverflow.com/a/22237794
        /// </remarks>
        private X509Certificate2 GenerateSelfSignedCertificate(string subjectName, string issuerName, AsymmetricKeyParameter issuerPrivKey, int keyStrength, TimeSpan lifespan)
        {
            // Generating Random Numbers
            var random = new SecureRandom();
            

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            certificateGenerator.SetSerialNumber(GenerateSerial());

            // Issuer and Subject Name
            var subjectDN = new X509Name(subjectName);
            var issuerDN = new X509Name(issuerName);
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

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
            var signatureFactory = new Asn1SignatureFactory(CertificateAuthority.SignatureAlg, issuerPrivKey, random);
            var certificate = certificateGenerator.Generate(signatureFactory);

            // correcponding private key
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(subjectKeyPair.Private);


            // merge into X509Certificate2
            var x509 = new X509Certificate2(certificate.GetEncoded());

            var seq = (Asn1Sequence)Asn1Object.FromByteArray(info.ParsePrivateKey().GetDerEncoded());
            if (seq.Count != 9)
                throw new InvalidOperationException("malformed sequence in RSA private key");

            //var rsa = new RsaPrivateKeyStructure(seq);
            var rsa = RsaPrivateKeyStructure.GetInstance(seq);
            var rsaparams = new RsaPrivateCrtKeyParameters(
                rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);


            x509.PrivateKey = DotNetUtilities.ToRSA(rsaparams);
            return x509;

        }

        /// <summary>
        /// serial prelude for cert
        /// </summary>
        /// <returns>0x0101</returns>
        internal override IEnumerable<byte> GetSerialPrelude()
        {
            return new byte[] { 0x01, 0x01 };
        }
    }
}
