// <copyright file="SHA256RIPEMD160.cs" company="Modular Bitcoin Cash">
// Copyright (c) 2018-2018 Modular Bitcoin Cash developers.
// Distributed under the MIT software license, see the accompanying LICENSE file in the project root
// or http://www.opensource.org/licenses/mit-license.php for full license information.
// </copyright>

namespace MBitcoinCash.HashProvider
{
    using System.Security.Cryptography;

    /// <summary>
    /// Hash provider implementing SHA256 + RIPEMD160 hash calculation.
    /// </summary>
    /// <seealso cref="MBitcoinCash.HashProvider.IHashProvider" />
    public class SHA256RIPEMD160 : IHashProvider
    {
        /// <inheritdoc/>
        public byte[] ComputeHash(byte[] input)
        {
            var sha256 = SHA256.Create();
            var firstHash = sha256.ComputeHash(input);
            var ripemd160 = RIPEMD160.Create();
            var secondHash = ripemd160.ComputeHash(firstHash);
            return secondHash;
        }
    }
}
