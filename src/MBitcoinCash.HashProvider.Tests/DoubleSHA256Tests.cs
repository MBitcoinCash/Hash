// <copyright file="DoubleSHA256Tests.cs" company="Modular Bitcoin Cash">
// Copyright (c) 2018-2018 Modular Bitcoin Cash developers.
// Distributed under the MIT software license, see the accompanying LICENSE file in the project root
// or http://www.opensource.org/licenses/mit-license.php for full license information.
// </copyright>

namespace MBitcoinCash.HashProvider.Tests
{
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    /// <summary>
    /// Tests for <seealso cref="DoubleSHA256"/> class.
    /// </summary>
    [TestClass]
    public class DoubleSHA256Tests
    {
        /// <summary>
        /// Checks that calculated has is correct.
        /// </summary>
        /// <remarks>
        /// Test is based on the Bitcoin transaction: https://blockchain.info/tx/74d350ca44c324f4643274b98801f9a023b2b8b72e8e895879fd9070a68f7f1f?format=hex
        /// </remarks>
        [TestMethod]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "String is in hex format, so it does not have any characters affected by conversion to lower.")]
        public void CalculateDoubleSHA256Hash()
        {
            var inputString = "02000000019b69251560ea1143de610b3c6630dcf94e12000ceba7d40b136bfb67f5a9e4eb000000006b483045022100a52f6c484072528334ac4aa5605a3f440c47383e01bc94e9eec043d5ad7e2c8002206439555804f22c053b89390958083730d6a66c1b711f6b8669a025dbbf5575bd012103abc7f1683755e94afe899029a8acde1480716385b37d4369ba1bed0a2eb3a0c5feffffff022864f203000000001976a914a2420e28fbf9b3bd34330ebf5ffa544734d2bfc788acb1103955000000001976a9149049b676cf05040103135c7342bcc713a816700688ac3bc50700".ToLowerInvariant();
            var hashString = "74d350ca44c324f4643274b98801f9a023b2b8b72e8e895879fd9070a68f7f1f";

            var input = inputString.ToByteArray();

            var hashProvider = new DoubleSHA256();
            var computedHash = hashProvider.ComputeHash(input);
            Assert.AreEqual(hashString, computedHash.ToHexString());
        }
    }
}
