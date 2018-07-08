// <copyright file="StringToByteArrayConverter.cs" company="Modular Bitcoin Cash">
// Copyright (c) 2018-2018 Modular Bitcoin Cash developers.
// Distributed under the MIT software license, see the accompanying LICENSE file in the project root
// or http://www.opensource.org/licenses/mit-license.php for full license information.
// </copyright>

namespace MBitcoinCash.HashProvider.Tests
{
    using System;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Converts string representation of byte array to real byte array.
    /// </summary>
    internal static class StringToByteArrayConverter
    {
        /// <summary>
        /// To the byte array.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>The byte array.</returns>
        internal static byte[] TransactionHexToByteArray(this string input)
        {
            return Enumerable.Range(0, input.Length / 2).Select(x => Convert.ToByte(input.Substring(x * 2, 2), 16)).ToArray();
        }

        /// <summary>
        /// To the byte array.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>The byte array.</returns>
        internal static byte[] ToByteArray(this string input)
        {
            return Encoding.ASCII.GetBytes(input);
        }

        /// <summary>
        /// To the hexadecimal string.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>The string representation of byte array.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "This is hash in hex format, so it does not have any characters affected by conversion to lower.")]
        internal static string ToHexTransactionId(this byte[] input)
        {
            var reversedArray = new byte[input.Length];
            input.CopyTo(reversedArray, 0);
            Array.Reverse(reversedArray);

            return BitConverter.ToString(reversedArray).Replace("-", string.Empty, StringComparison.InvariantCulture).ToLowerInvariant();
        }

        /// <summary>
        /// To the hexadecimal string.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>The string representation of byte array.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "This is hash in hex format, so it does not have any characters affected by conversion to lower.")]
        internal static string ToHexString(this byte[] input)
        {
            return BitConverter.ToString(input).Replace("-", string.Empty, StringComparison.InvariantCulture).ToLowerInvariant();
        }
    }
}
