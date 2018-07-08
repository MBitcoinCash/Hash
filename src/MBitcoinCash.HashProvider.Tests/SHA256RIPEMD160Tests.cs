// <copyright file="SHA256RIPEMD160Tests.cs" company="Modular Bitcoin Cash">
// Copyright (c) 2018-2018 Modular Bitcoin Cash developers.
// Distributed under the MIT software license, see the accompanying LICENSE file in the project root
// or http://www.opensource.org/licenses/mit-license.php for full license information.
// </copyright>

namespace MBitcoinCash.HashProvider.Tests
{
    using System.Text;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    /// <summary>
    /// Tests for <seealso cref="SHA256RIPEMD160"/> class.
    /// </summary>
    [TestClass]
    public class SHA256RIPEMD160Tests
    {
        /// <summary>
        /// Checks that calculated hash is correct.
        /// </summary>
        /// <remarks>
        /// Test is based on Bitcoin documentation sample: https://en.bitcoin.it/wiki/Protocol_documentation#Differential_encoding
        /// </remarks>
        [TestMethod]
        public void CalculateDoubleSHA256Hash()
        {
            var inputString = "hello";
            var hashString = "b6a9c8c230722b7c748331a8b450f05566dc7d0f";

            var input = inputString.ToByteArray();

            var hashProvider = new SHA256RIPEMD160();
            var computedHash = hashProvider.ComputeHash(input);
            Assert.AreEqual(hashString, computedHash.ToHexString());
        }
    }
}
