// <copyright file="RIPEMD160.cs" company="Modular Bitcoin Cash">
// Copyright (c) 2018-2018 Modular Bitcoin Cash developers.
// Distributed under the MIT software license, see the accompanying LICENSE file in the project root
// or http://www.opensource.org/licenses/mit-license.php for full license information.
// </copyright>

namespace MBitcoinCash.HashProvider
{
    using System.Security.Cryptography;

    /// <summary>
    /// Implements RIPEMD160 hashing algorithm.
    /// </summary>
    /// <remarks>
    /// Original code taken from https://github.com/darrenstarr/RIPEMD160.net
    /// </remarks>
    /// <seealso cref="System.Security.Cryptography.HashAlgorithm" />
    public abstract class RIPEMD160 : HashAlgorithm
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RIPEMD160"/> class.
        /// </summary>
        protected RIPEMD160()
        {
        }

        /// <summary>
        /// Creates the instance of <see cref="RIPEMD160"/>.
        /// </summary>
        /// <returns>The instance of <see cref="RIPEMD160"/></returns>
        public static RIPEMD160 Create()
        {
            return new RIPEMD160Managed();
        }
    }
}