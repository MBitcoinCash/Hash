// <copyright file="RIPEMD160Tests.cs" company="Modular Bitcoin Cash">
// Copyright (c) 2018-2018 Modular Bitcoin Cash developers.
// Distributed under the MIT software license, see the accompanying LICENSE file in the project root
// or http://www.opensource.org/licenses/mit-license.php for full license information.
// </copyright>

namespace MBitcoinCash.HashProvider.Tests
{
    using System.Linq;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    /// <summary>
    /// Tests for <seealso cref="RIPEMD160"/> class
    /// </summary>
    [TestClass]
    public class RIPEMD160Tests
    {
        /// <summary>
        /// RIPEMD160 hash for empty string is correct.
        /// </summary>
        /// <remarks>
        /// Test based on sample from: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
        /// </remarks>
        [TestMethod]
        public void RIPEMD160Empty()
        {
            var ripemd160 = RIPEMD160.Create();
            var result = ripemd160.ComputeHash(string.Empty.ToByteArray());

            Assert.AreEqual("9c1185a5c5e9fc54612808977ee8f548b2258d31", result.ToHexString());
        }

        /// <summary>
        /// RIPEMD160 hash for "abc" is correct.
        /// </summary>
        /// <remarks>
        /// Test based on sample from: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
        /// </remarks>
        [TestMethod]
        public void RIPEMD160abc()
        {
            var ripemd160 = RIPEMD160.Create();
            var result = ripemd160.ComputeHash("abc".ToByteArray());

            Assert.AreEqual("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", result.ToHexString());
        }

        /// <summary>
        /// RIPEMD160 hash for lower letters string is correct.
        /// </summary>
        /// <remarks>
        /// Test based on sample from: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
        /// </remarks>
        [TestMethod]
        public void RIPEMD160LowerLetters()
        {
            var ripemd160 = RIPEMD160.Create();
            var result = ripemd160.ComputeHash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".ToByteArray());

            Assert.AreEqual("12a053384a9c0c88e405a06c27dcf49ada62eb2b", result.ToHexString());
        }

        /// <summary>
        /// RIPEMD160 hash for a full alphabet is correct.
        /// </summary>
        /// <remarks>
        /// Test based on sample from: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
        /// </remarks>
        [TestMethod]
        public void RIPEMD160FullAlphabet()
        {
            var ripemd160 = RIPEMD160.Create();
            var result = ripemd160.ComputeHash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToByteArray());

            Assert.AreEqual("b0e20b6e3116640286ed3a87a5713079b21f5189", result.ToHexString());
        }

        /// <summary>
        /// RIPEMD160 hash for one million a's is correct.
        /// </summary>
        /// <remarks>
        /// Test based on sample from: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
        /// </remarks>
        [TestMethod]
        public void RIPEMD160MillionA()
        {
            var ripemd160 = RIPEMD160.Create();
            var input = string.Join(string.Empty, Enumerable.Repeat<string>("a", 1000000));
            var result = ripemd160.ComputeHash(input.ToByteArray());

            Assert.AreEqual("52783243c1697bdbe16d37f97f68f08325dc1528", result.ToHexString());
        }
    }
}