// <copyright file="IHashProvider.cs" company="Modular Bitcoin Cash">
// Copyright (c) 2018-2018 Modular Bitcoin Cash developers.
// Distributed under the MIT software license, see the accompanying LICENSE file in the project root
// or http://www.opensource.org/licenses/mit-license.php for full license information.
// </copyright>

namespace MBitcoinCash.HashProvider
{
    /// <summary>
    /// Interface for the object that can compute the hash.
    /// </summary>
    public interface IHashProvider
    {
        /// <summary>
        /// Computes the hash from provided input.
        /// </summary>
        /// <param name="input">The input data.</param>
        /// <returns>The calculated hash.</returns>
        byte[] ComputeHash(byte[] input);
    }
}
