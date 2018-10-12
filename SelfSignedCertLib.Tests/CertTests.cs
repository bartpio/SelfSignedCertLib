using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SelfSignedCertLib;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Diagnostics;

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
        /// test ca input/output
        /// </summary>
        [TestMethod]
        public void TestCA_InputOutput()
        {
            var ca = new CertificateAuthority("CN=somethingggg about this makes it good for ephemeral use ONLY", 2048, TimeSpan.FromDays(365 * 20));  //,O=codercapital,OU=for ephemeral use
            var pbuf = ca.PublicKey.Export(X509ContentType.Pfx);
            var tfil = Path.GetTempFileName();
            File.WriteAllBytes(tfil, pbuf);

            var readit = new X509Certificate2(tfil);
            StringAssert.Contains(readit.SubjectName.Name, "CN=something");
            //StringAssert.Contains(readit.SubjectName.Name, "O=codercapital");
            //StringAssert.Contains(readit.SubjectName.Name, "OU=for ephemeral use");


            var somethings = ca.ToXml();
            Assert.IsNotNull(somethings);

            TestLoadupCAandMakeCert(somethings);
        }

        /// <summary>
        /// test loadup ca and make cert
        /// </summary>
        /// <param name="xmlstring"></param>
        private void TestLoadupCAandMakeCert(string xmlstring)
        {
            var sw = Stopwatch.StartNew();
            var ca = CertificateAuthority.FromXmlString(xmlstring);
            var catim = sw.ElapsedMilliseconds;
            var cermaker = new Certificate(ca, "CN=actualcer", 0, TimeSpan.FromMinutes(3));
            var cer = cermaker.Cert;
            Assert.IsNotNull(cer);
            Assert.IsTrue(cer.HasPrivateKey);
            sw.Stop();

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
