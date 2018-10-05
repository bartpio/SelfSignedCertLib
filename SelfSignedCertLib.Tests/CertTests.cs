using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SelfSignedCertLib;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace SelfSignedCertLib.Tests
{
    /// <summary>
    /// tests
    /// </summary>
    [TestClass]
    public class CertTests
    {
        /// <summary>
        /// test CA
        /// </summary>
        [TestMethod]
        public void TestCA()
        {
            var ca = new CertificateAuthority("CN=something");
            var pbuf = ca.PublicKey.Export(X509ContentType.Pfx);
            var tfil = Path.GetTempFileName();
            File.WriteAllBytes(tfil, pbuf);

            var readit = new X509Certificate2(tfil);
            Assert.AreEqual("CN=something", readit.SubjectName.Name);
        }

        /// <summary>
        /// test CA and actual cert
        /// </summary>
        [TestMethod]
        public void TestCert()
        {
            var ca = new CertificateAuthority("CN=something");
            var cermaker = new Certificate(ca, "CN=actual");
            var cer = cermaker.Cert;
            Assert.IsNotNull(cer);
            Assert.IsTrue(cer.HasPrivateKey);

            var cp = new X509ChainPolicy();
            cp.ExtraStore.Add(ca.PublicKey);
            cp.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            cp.RevocationMode = X509RevocationMode.NoCheck;
            cp.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
            

            var chain = new X509Chain
            {
                ChainPolicy = cp
            };

            var built = chain.Build(cer);
            Assert.IsTrue(built, "should have built a validated chain");
            Assert.IsTrue(chain.ChainElements.Cast<X509ChainElement>().Select(x => x.Certificate).Contains(ca.PublicKey), "expecting chain to have our generated CA");
            Assert.IsTrue(chain.ChainElements.Cast<X509ChainElement>().Select(x => x.Certificate).Contains(cer), "expecting chain to have our actual cert");
            Assert.AreEqual(2, chain.ChainElements.Count, "chain element count");
        }
    }
}
