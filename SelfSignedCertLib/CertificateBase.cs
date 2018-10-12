using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SelfSignedCertLib
{
    /// <summary>
    /// certprocessor base
    /// some helpers shared among Certificate Authority and end Certificate
    /// </summary>
    public abstract class CertificateBase
    {
        /// <summary>
        /// cons
        /// </summary>
        internal CertificateBase()
        {
        }

        /// <summary>
        /// randomness
        /// </summary>
        internal readonly SecureRandom _rand = new SecureRandom();

        /// <summary>
        /// assign life
        /// </summary>
        /// <param name="gen"></param>
        /// <param name="lifespan"></param>
        internal void AssignLife(X509V3CertificateGenerator gen, TimeSpan lifespan)
        {
            var now = DateTime.UtcNow;
            var notBefore = now.Subtract(TimeSpan.FromHours(2)); //account for clockdrift etc.
            var notAfter = now + lifespan;  //we get back a DateTime. neat.
            gen.SetNotBefore(notBefore);
            gen.SetNotAfter(notAfter);
        }

        /// <summary>
        /// get serial prelude
        /// </summary>
        /// <returns></returns>
        internal abstract IEnumerable<byte> GetSerialPrelude();

        /// <summary>
        /// gen serial
        /// incorporates prelude, utc ticks, 128 bits of secure random
        /// </summary>
        /// <returns></returns>
        internal BigInteger GenerateSerial()
        {
            var randbuf = new byte[128 / 8];  //we'll pull 128 bits of secure random
            _rand.NextBytes(randbuf);
            var buf = GetSerialPrelude().Concat(BitConverter.GetBytes(DateTime.UtcNow.Ticks)).Concat(randbuf).ToArray();
            return new BigInteger(1, buf);  //return positive biginteger
        }
    }
}
