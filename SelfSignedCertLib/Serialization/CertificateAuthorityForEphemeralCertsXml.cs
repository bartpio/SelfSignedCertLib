using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace SelfSignedCertLib.Serialization
{
    /// <summary>
    /// somewhat proprietary but simple serialization mechanism
    /// </summary>
    /// <remarks>
    /// various human readable attributes here are redundant with information stashed deep within the PublicKeyData bytes
    /// </remarks>
    [Serializable]
    [XmlRoot(ElementName = "CertificateAuthorityForEphemeralCerts", Namespace = "http://example.org/schemas/SelfSignedCertLib/Serialization", IsNullable = false)]
    public sealed class CertificateAuthorityForEphemeralCertsXml
    {
        /// <summary>
        /// serial number
        /// </summary>
        [XmlAttribute]
        public string SerialNumber { get; set; }

        /// <summary>
        /// subj
        /// </summary>
        [XmlElement(IsNullable = false)]
        public string SubjectName { get; set; }

        /// <summary>
        /// expiration string
        /// </summary>
        [XmlElement(IsNullable = false)]
        public string Expires { get; set; }

        /// <summary>
        /// thumb
        /// </summary>
        [XmlElement(IsNullable = false)]
        public string Thumbprint { get; set; }

        /// <summary>
        /// results of x509certificate2 export
        /// </summary>
        [XmlElement(IsNullable = false)]
        public byte[] PublicKeyData { get; set; }

        /// <summary>
        /// rsa private key parameters
        /// </summary>
        [XmlElement(IsNullable = false)]
        public RSAParameters PrivateKeyParameters { get; set; }       
    }
}
