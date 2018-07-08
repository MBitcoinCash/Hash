// <copyright file="RIPEMD160Managed.cs" company="Modular Bitcoin Cash">
// Copyright (c) 2018-2018 Modular Bitcoin Cash developers.
// Distributed under the MIT software license, see the accompanying LICENSE file in the project root
// or http://www.opensource.org/licenses/mit-license.php for full license information.
// </copyright>

namespace MBitcoinCash.HashProvider
{
    using System;
    using System.Linq;

    /// <summary>
    /// Implements RIPEMD160 hashing algorithm in managed code.
    /// </summary>
    /// <remarks>
    /// Original code taken from https://github.com/darrenstarr/RIPEMD160.net
    /// </remarks>
    /// <seealso cref="MBitcoinCash.HashProvider.RIPEMD160" />
    public class RIPEMD160Managed : RIPEMD160
    {
        /// <summary>
        /// The size of the message in RIPEMD160 hash.
        /// </summary>
        private const int MessageSize = 160;

        /// <summary>
        /// The buffer that accumulates and stores intermediate result.
        /// </summary>
        private uint[] resultBuffer = new uint[MessageSize / 32];

        /// <summary>
        /// The current message buffer
        /// </summary>
        private uint[] currentMessageBuffer = new uint[16];

        /// <summary>
        /// The unhashed buffer
        /// </summary>
        private byte[] unhashedBuffer = new byte[64];

        /// <summary>
        /// The length of unhashed buffer.
        /// </summary>
        private int unhashedBufferLength = 0;

        /// <summary>
        /// Tracks lenght of hashed data.
        /// </summary>
        private uint hashedLength = 0;

        /// <summary>
        /// Initializes a new instance of the <see cref="RIPEMD160Managed"/> class.
        /// </summary>
        public RIPEMD160Managed()
        {
            this.Initialize();
        }

        /// <inheritdoc/>
        public override void Initialize()
        {
            // initialize message buffer with "magic values"
            this.resultBuffer[0] = 0x67452301;
            this.resultBuffer[1] = 0xefcdab89;
            this.resultBuffer[2] = 0x98badcfe;
            this.resultBuffer[3] = 0x10325476;
            this.resultBuffer[4] = 0xc3d2e1f0;

            this.currentMessageBuffer = Enumerable.Repeat(0U, 16).ToArray();
            this.hashedLength = 0;
            this.unhashedBufferLength = 0;
        }

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            var index = 0;
            while (index < cbSize)
            {
                var bytesRemaining = cbSize - index;
                if (this.unhashedBufferLength > 0)
                {
                    if ((bytesRemaining + this.unhashedBufferLength) >= this.unhashedBuffer.Length)
                    {
                        Array.Copy(array, ibStart + index, this.unhashedBuffer, this.unhashedBufferLength, this.unhashedBuffer.Length - this.unhashedBufferLength);
                        index += this.unhashedBuffer.Length - this.unhashedBufferLength;
                        this.unhashedBufferLength = this.unhashedBuffer.Length;

                        for (var i = 0; i < 16; i++)
                        {
                            this.currentMessageBuffer[i] = ReadUInt32(this.unhashedBuffer, i * 4);
                        }

                        this.resultBuffer = ProcessBlock(this.resultBuffer, this.currentMessageBuffer);
                        this.unhashedBufferLength = 0;
                    }
                    else
                    {
                        Array.Copy(array, ibStart + index, this.unhashedBuffer, this.unhashedBufferLength, bytesRemaining);
                        this.unhashedBufferLength += bytesRemaining;
                        index += bytesRemaining;
                    }
                }
                else
                {
                    if (bytesRemaining >= this.unhashedBuffer.Length)
                    {
                        for (var i = 0; i < 16; i++)
                        {
                            this.currentMessageBuffer[i] = ReadUInt32(array, index + (i * 4));
                        }

                        index += this.unhashedBuffer.Length;

                        this.resultBuffer = ProcessBlock(this.resultBuffer, this.currentMessageBuffer);
                    }
                    else
                    {
                        Array.Copy(array, ibStart + index, this.unhashedBuffer, 0, bytesRemaining);
                        this.unhashedBufferLength = bytesRemaining;
                        index += bytesRemaining;
                    }
                }
            }

            this.hashedLength += (uint)cbSize;
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            ProcessLastBlock(ref this.resultBuffer, this.unhashedBuffer, this.hashedLength);

            var result = new byte[MessageSize / 8];

            for (var i = 0; i < MessageSize / 8; i += 4)
            {
                result[i] = Convert.ToByte(this.resultBuffer[i >> 2] & 0xFF);         /* implicit cast to byte  */
                result[i + 1] = Convert.ToByte((this.resultBuffer[i >> 2] >> 8) & 0xFF);  /*  extracts the 8 least  */
                result[i + 2] = Convert.ToByte((this.resultBuffer[i >> 2] >> 16) & 0xFF);  /*  significant bits.     */
                result[i + 3] = Convert.ToByte((this.resultBuffer[i >> 2] >> 24) & 0xFF);
            }

            return result;
        }

        /// <summary>
        /// Reads the <seealso cref="uint"/> value from specified location in the buffer.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <param name="offset">The offset.</param>
        /// <returns>The value read from buffer.</returns>
        private static uint ReadUInt32(byte[] buffer, long offset)
        {
            return
                (Convert.ToUInt32(buffer[3 + offset]) << 24) |
                (Convert.ToUInt32(buffer[2 + offset]) << 16) |
                (Convert.ToUInt32(buffer[1 + offset]) << 8) |
                Convert.ToUInt32(buffer[0 + offset]);
        }

        /// <summary>
        /// Rotates bits to the left left.
        /// </summary>
        /// <param name="value">The original value.</param>
        /// <param name="bits">The number of bits to rotate.</param>
        /// <returns>The rotated value.</returns>
        private static uint RotateLeft(uint value, int bits)
            => (value << bits) | (value >> (32 - bits));

        /// <summary>
        /// The first of the five basic transformation functions used in RIPEMD160 caluclations.
        /// </summary>
        /// <param name="x">The x.</param>
        /// <param name="y">The y.</param>
        /// <param name="z">The z.</param>
        /// <returns>The transformation result.</returns>
        private static uint F(uint x, uint y, uint z)
            => x ^ y ^ z;

        /// <summary>
        /// The second of the five basic transformation functions used in RIPEMD160 caluclations.
        /// </summary>
        /// <param name="x">The x.</param>
        /// <param name="y">The y.</param>
        /// <param name="z">The z.</param>
        /// <returns>The transformation result.</returns>
        private static uint G(uint x, uint y, uint z)
            => (x & y) | (~x & z);

        /// <summary>
        /// The third of the five basic transformation functions used in RIPEMD160 caluclations.
        /// </summary>
        /// <param name="x">The x.</param>
        /// <param name="y">The y.</param>
        /// <param name="z">The z.</param>
        /// <returns>The transformation result.</returns>
        private static uint H(uint x, uint y, uint z)
            => (x | ~y) ^ z;

        /// <summary>
        /// The fourth of the five basic transformation functions used in RIPEMD160 caluclations.
        /// </summary>
        /// <param name="x">The x.</param>
        /// <param name="y">The y.</param>
        /// <param name="z">The z.</param>
        /// <returns>The transformation result.</returns>
        private static uint I(uint x, uint y, uint z)
            => (x & z) | (y & ~z);

        /// <summary>
        /// The fift of the five basic transformation functions used in RIPEMD160 caluclations.
        /// </summary>
        /// <param name="x">The x.</param>
        /// <param name="y">The y.</param>
        /// <param name="z">The z.</param>
        /// <returns>The transformation result.</returns>
        private static uint J(uint x, uint y, uint z)
            => x ^ (y | ~z);

        /// <summary>
        /// The calculation of first left round.
        /// </summary>
        /// <param name="a">a.</param>
        /// <param name="b">The b.</param>
        /// <param name="c">The c.</param>
        /// <param name="d">The d.</param>
        /// <param name="e">The e.</param>
        /// <param name="message">The message byte.</param>
        /// <param name="rotationCount">The number of bits to rotate.</param>
        private static void LeftRound1(ref uint a, uint b, ref uint c, uint d, uint e, uint message, int rotationCount)
        {
            a += F(b, c, d) + message;
            a = RotateLeft(a, rotationCount) + e;
            c = RotateLeft(c, 10);
        }

        /// <summary>
        /// The calculation of second left round.
        /// </summary>
        /// <param name="a">a.</param>
        /// <param name="b">The b.</param>
        /// <param name="c">The c.</param>
        /// <param name="d">The d.</param>
        /// <param name="e">The e.</param>
        /// <param name="message">The message byte.</param>
        /// <param name="rotationCount">The number of bits to rotate.</param>
        private static void LeftRound2(ref uint a, uint b, ref uint c, uint d, uint e, uint message, int rotationCount)
        {
            a += G(b, c, d) + message + 0x5a827999U;
            a = RotateLeft(a, rotationCount) + e;
            c = RotateLeft(c, 10);
        }

        /// <summary>
        /// The calculation of third left round.
        /// </summary>
        /// <param name="a">a.</param>
        /// <param name="b">The b.</param>
        /// <param name="c">The c.</param>
        /// <param name="d">The d.</param>
        /// <param name="e">The e.</param>
        /// <param name="message">The message byte.</param>
        /// <param name="rotationCount">The number of bits to rotate.</param>
        private static void LeftRound3(ref uint a, uint b, ref uint c, uint d, uint e, uint message, int rotationCount)
        {
            a += H(b, c, d) + message + 0x6ed9eba1U;
            a = RotateLeft(a, rotationCount) + e;
            c = RotateLeft(c, 10);
        }

        /// <summary>
        /// The calculation of fourth left round.
        /// </summary>
        /// <param name="a">a.</param>
        /// <param name="b">The b.</param>
        /// <param name="c">The c.</param>
        /// <param name="d">The d.</param>
        /// <param name="e">The e.</param>
        /// <param name="message">The message byte.</param>
        /// <param name="rotationCount">The number of bits to rotate.</param>
        private static void LeftRound4(ref uint a, uint b, ref uint c, uint d, uint e, uint message, int rotationCount)
        {
            a += I(b, c, d) + message + 0x8f1bbcdcU;
            a = RotateLeft(a, rotationCount) + e;
            c = RotateLeft(c, 10);
        }

        /// <summary>
        /// The calculation of fifth left round.
        /// </summary>
        /// <param name="a">a.</param>
        /// <param name="b">The b.</param>
        /// <param name="c">The c.</param>
        /// <param name="d">The d.</param>
        /// <param name="e">The e.</param>
        /// <param name="message">The message byte.</param>
        /// <param name="rotationCount">The number of bits to rotate.</param>
        private static void LeftRound5(ref uint a, uint b, ref uint c, uint d, uint e, uint message, int rotationCount)
        {
            a += J(b, c, d) + message + 0xa953fd4eU;
            a = RotateLeft(a, rotationCount) + e;
            c = RotateLeft(c, 10);
        }

        /// <summary>
        /// The calculation of first right round.
        /// </summary>
        /// <param name="a">a.</param>
        /// <param name="b">The b.</param>
        /// <param name="c">The c.</param>
        /// <param name="d">The d.</param>
        /// <param name="e">The e.</param>
        /// <param name="message">The message byte.</param>
        /// <param name="rotationCount">The number of bits to rotate.</param>
        private static void RightRound1(ref uint a, uint b, ref uint c, uint d, uint e, uint message, int rotationCount)
        {
            a += J(b, c, d) + message + 0x50a28be6U;
            a = RotateLeft(a, rotationCount) + e;
            c = RotateLeft(c, 10);
        }

        /// <summary>
        /// The calculation of second right round.
        /// </summary>
        /// <param name="a">a.</param>
        /// <param name="b">The b.</param>
        /// <param name="c">The c.</param>
        /// <param name="d">The d.</param>
        /// <param name="e">The e.</param>
        /// <param name="message">The message byte.</param>
        /// <param name="rotationCount">The number of bits to rotate.</param>
        private static void RightRound2(ref uint a, uint b, ref uint c, uint d, uint e, uint message, int rotationCount)
        {
            a += I(b, c, d) + message + 0x5c4dd124U;
            a = RotateLeft(a, rotationCount) + e;
            c = RotateLeft(c, 10);
        }

        /// <summary>
        /// The calculation of third right round.
        /// </summary>
        /// <param name="a">a.</param>
        /// <param name="b">The b.</param>
        /// <param name="c">The c.</param>
        /// <param name="d">The d.</param>
        /// <param name="e">The e.</param>
        /// <param name="message">The message byte.</param>
        /// <param name="rotationCount">The number of bits to rotate.</param>
        private static void RightRound3(ref uint a, uint b, ref uint c, uint d, uint e, uint message, int rotationCount)
        {
            a += H(b, c, d) + message + 0x6d703ef3U;
            a = RotateLeft(a, rotationCount) + e;
            c = RotateLeft(c, 10);
        }

        /// <summary>
        /// The calculation of fourth right round.
        /// </summary>
        /// <param name="a">a.</param>
        /// <param name="b">The b.</param>
        /// <param name="c">The c.</param>
        /// <param name="d">The d.</param>
        /// <param name="e">The e.</param>
        /// <param name="message">The message byte.</param>
        /// <param name="rotationCount">The number of bits to rotate.</param>
        private static void RightRound4(ref uint a, uint b, ref uint c, uint d, uint e, uint message, int rotationCount)
        {
            a += G(b, c, d) + message + 0x7a6d76e9U;
            a = RotateLeft(a, rotationCount) + e;
            c = RotateLeft(c, 10);
        }

        /// <summary>
        /// The calculation of fourth right round.
        /// </summary>
        /// <param name="a">a.</param>
        /// <param name="b">The b.</param>
        /// <param name="c">The c.</param>
        /// <param name="d">The d.</param>
        /// <param name="e">The e.</param>
        /// <param name="message">The message byte.</param>
        /// <param name="rotationCount">The number of bits to rotate.</param>
        private static void RightRound5(ref uint a, uint b, ref uint c, uint d, uint e, uint message, int rotationCount)
        {
            a += F(b, c, d) + message;
            a = RotateLeft(a, rotationCount) + e;
            c = RotateLeft(c, 10);
        }

        /// <summary>
        /// Processes single block through hash algorithm.
        /// </summary>
        /// <param name="previousHash">The hash from previous block.</param>
        /// <param name="messageBlock">The message block.</param>
        /// <returns>The hash after processing message block.</returns>
        private static uint[] ProcessBlock(uint[] previousHash, uint[] messageBlock)
        {
            uint a = previousHash[0];
            uint b = previousHash[1];
            uint c = previousHash[2];
            uint d = previousHash[3];
            uint e = previousHash[4];
            uint aa = a;
            uint bb = b;
            uint cc = c;
            uint dd = d;
            uint ee = e;

            /* round 1 */
            LeftRound1(ref a, b, ref c, d, e, messageBlock[0], 11);
            LeftRound1(ref e, a, ref b, c, d, messageBlock[1], 14);
            LeftRound1(ref d, e, ref a, b, c, messageBlock[2], 15);
            LeftRound1(ref c, d, ref e, a, b, messageBlock[3], 12);
            LeftRound1(ref b, c, ref d, e, a, messageBlock[4], 5);
            LeftRound1(ref a, b, ref c, d, e, messageBlock[5], 8);
            LeftRound1(ref e, a, ref b, c, d, messageBlock[6], 7);
            LeftRound1(ref d, e, ref a, b, c, messageBlock[7], 9);
            LeftRound1(ref c, d, ref e, a, b, messageBlock[8], 11);
            LeftRound1(ref b, c, ref d, e, a, messageBlock[9], 13);
            LeftRound1(ref a, b, ref c, d, e, messageBlock[10], 14);
            LeftRound1(ref e, a, ref b, c, d, messageBlock[11], 15);
            LeftRound1(ref d, e, ref a, b, c, messageBlock[12], 6);
            LeftRound1(ref c, d, ref e, a, b, messageBlock[13], 7);
            LeftRound1(ref b, c, ref d, e, a, messageBlock[14], 9);
            LeftRound1(ref a, b, ref c, d, e, messageBlock[15], 8);

            /* round 2 */
            LeftRound2(ref e, a, ref b, c, d, messageBlock[7], 7);
            LeftRound2(ref d, e, ref a, b, c, messageBlock[4], 6);
            LeftRound2(ref c, d, ref e, a, b, messageBlock[13], 8);
            LeftRound2(ref b, c, ref d, e, a, messageBlock[1], 13);
            LeftRound2(ref a, b, ref c, d, e, messageBlock[10], 11);
            LeftRound2(ref e, a, ref b, c, d, messageBlock[6], 9);
            LeftRound2(ref d, e, ref a, b, c, messageBlock[15], 7);
            LeftRound2(ref c, d, ref e, a, b, messageBlock[3], 15);
            LeftRound2(ref b, c, ref d, e, a, messageBlock[12], 7);
            LeftRound2(ref a, b, ref c, d, e, messageBlock[0], 12);
            LeftRound2(ref e, a, ref b, c, d, messageBlock[9], 15);
            LeftRound2(ref d, e, ref a, b, c, messageBlock[5], 9);
            LeftRound2(ref c, d, ref e, a, b, messageBlock[2], 11);
            LeftRound2(ref b, c, ref d, e, a, messageBlock[14], 7);
            LeftRound2(ref a, b, ref c, d, e, messageBlock[11], 13);
            LeftRound2(ref e, a, ref b, c, d, messageBlock[8], 12);

            /* round 3 */
            LeftRound3(ref d, e, ref a, b, c, messageBlock[3], 11);
            LeftRound3(ref c, d, ref e, a, b, messageBlock[10], 13);
            LeftRound3(ref b, c, ref d, e, a, messageBlock[14], 6);
            LeftRound3(ref a, b, ref c, d, e, messageBlock[4], 7);
            LeftRound3(ref e, a, ref b, c, d, messageBlock[9], 14);
            LeftRound3(ref d, e, ref a, b, c, messageBlock[15], 9);
            LeftRound3(ref c, d, ref e, a, b, messageBlock[8], 13);
            LeftRound3(ref b, c, ref d, e, a, messageBlock[1], 15);
            LeftRound3(ref a, b, ref c, d, e, messageBlock[2], 14);
            LeftRound3(ref e, a, ref b, c, d, messageBlock[7], 8);
            LeftRound3(ref d, e, ref a, b, c, messageBlock[0], 13);
            LeftRound3(ref c, d, ref e, a, b, messageBlock[6], 6);
            LeftRound3(ref b, c, ref d, e, a, messageBlock[13], 5);
            LeftRound3(ref a, b, ref c, d, e, messageBlock[11], 12);
            LeftRound3(ref e, a, ref b, c, d, messageBlock[5], 7);
            LeftRound3(ref d, e, ref a, b, c, messageBlock[12], 5);

            /* round 4 */
            LeftRound4(ref c, d, ref e, a, b, messageBlock[1], 11);
            LeftRound4(ref b, c, ref d, e, a, messageBlock[9], 12);
            LeftRound4(ref a, b, ref c, d, e, messageBlock[11], 14);
            LeftRound4(ref e, a, ref b, c, d, messageBlock[10], 15);
            LeftRound4(ref d, e, ref a, b, c, messageBlock[0], 14);
            LeftRound4(ref c, d, ref e, a, b, messageBlock[8], 15);
            LeftRound4(ref b, c, ref d, e, a, messageBlock[12], 9);
            LeftRound4(ref a, b, ref c, d, e, messageBlock[4], 8);
            LeftRound4(ref e, a, ref b, c, d, messageBlock[13], 9);
            LeftRound4(ref d, e, ref a, b, c, messageBlock[3], 14);
            LeftRound4(ref c, d, ref e, a, b, messageBlock[7], 5);
            LeftRound4(ref b, c, ref d, e, a, messageBlock[15], 6);
            LeftRound4(ref a, b, ref c, d, e, messageBlock[14], 8);
            LeftRound4(ref e, a, ref b, c, d, messageBlock[5], 6);
            LeftRound4(ref d, e, ref a, b, c, messageBlock[6], 5);
            LeftRound4(ref c, d, ref e, a, b, messageBlock[2], 12);

            /* round 5 */
            LeftRound5(ref b, c, ref d, e, a, messageBlock[4], 9);
            LeftRound5(ref a, b, ref c, d, e, messageBlock[0], 15);
            LeftRound5(ref e, a, ref b, c, d, messageBlock[5], 5);
            LeftRound5(ref d, e, ref a, b, c, messageBlock[9], 11);
            LeftRound5(ref c, d, ref e, a, b, messageBlock[7], 6);
            LeftRound5(ref b, c, ref d, e, a, messageBlock[12], 8);
            LeftRound5(ref a, b, ref c, d, e, messageBlock[2], 13);
            LeftRound5(ref e, a, ref b, c, d, messageBlock[10], 12);
            LeftRound5(ref d, e, ref a, b, c, messageBlock[14], 5);
            LeftRound5(ref c, d, ref e, a, b, messageBlock[1], 12);
            LeftRound5(ref b, c, ref d, e, a, messageBlock[3], 13);
            LeftRound5(ref a, b, ref c, d, e, messageBlock[8], 14);
            LeftRound5(ref e, a, ref b, c, d, messageBlock[11], 11);
            LeftRound5(ref d, e, ref a, b, c, messageBlock[6], 8);
            LeftRound5(ref c, d, ref e, a, b, messageBlock[15], 5);
            LeftRound5(ref b, c, ref d, e, a, messageBlock[13], 6);

            /* parallel round 1 */
            RightRound1(ref aa, bb, ref cc, dd, ee, messageBlock[5], 8);
            RightRound1(ref ee, aa, ref bb, cc, dd, messageBlock[14], 9);
            RightRound1(ref dd, ee, ref aa, bb, cc, messageBlock[7], 9);
            RightRound1(ref cc, dd, ref ee, aa, bb, messageBlock[0], 11);
            RightRound1(ref bb, cc, ref dd, ee, aa, messageBlock[9], 13);
            RightRound1(ref aa, bb, ref cc, dd, ee, messageBlock[2], 15);
            RightRound1(ref ee, aa, ref bb, cc, dd, messageBlock[11], 15);
            RightRound1(ref dd, ee, ref aa, bb, cc, messageBlock[4], 5);
            RightRound1(ref cc, dd, ref ee, aa, bb, messageBlock[13], 7);
            RightRound1(ref bb, cc, ref dd, ee, aa, messageBlock[6], 7);
            RightRound1(ref aa, bb, ref cc, dd, ee, messageBlock[15], 8);
            RightRound1(ref ee, aa, ref bb, cc, dd, messageBlock[8], 11);
            RightRound1(ref dd, ee, ref aa, bb, cc, messageBlock[1], 14);
            RightRound1(ref cc, dd, ref ee, aa, bb, messageBlock[10], 14);
            RightRound1(ref bb, cc, ref dd, ee, aa, messageBlock[3], 12);
            RightRound1(ref aa, bb, ref cc, dd, ee, messageBlock[12], 6);

            /* parallel round 2 */
            RightRound2(ref ee, aa, ref bb, cc, dd, messageBlock[6], 9);
            RightRound2(ref dd, ee, ref aa, bb, cc, messageBlock[11], 13);
            RightRound2(ref cc, dd, ref ee, aa, bb, messageBlock[3], 15);
            RightRound2(ref bb, cc, ref dd, ee, aa, messageBlock[7], 7);
            RightRound2(ref aa, bb, ref cc, dd, ee, messageBlock[0], 12);
            RightRound2(ref ee, aa, ref bb, cc, dd, messageBlock[13], 8);
            RightRound2(ref dd, ee, ref aa, bb, cc, messageBlock[5], 9);
            RightRound2(ref cc, dd, ref ee, aa, bb, messageBlock[10], 11);
            RightRound2(ref bb, cc, ref dd, ee, aa, messageBlock[14], 7);
            RightRound2(ref aa, bb, ref cc, dd, ee, messageBlock[15], 7);
            RightRound2(ref ee, aa, ref bb, cc, dd, messageBlock[8], 12);
            RightRound2(ref dd, ee, ref aa, bb, cc, messageBlock[12], 7);
            RightRound2(ref cc, dd, ref ee, aa, bb, messageBlock[4], 6);
            RightRound2(ref bb, cc, ref dd, ee, aa, messageBlock[9], 15);
            RightRound2(ref aa, bb, ref cc, dd, ee, messageBlock[1], 13);
            RightRound2(ref ee, aa, ref bb, cc, dd, messageBlock[2], 11);

            /* parallel round 3 */
            RightRound3(ref dd, ee, ref aa, bb, cc, messageBlock[15], 9);
            RightRound3(ref cc, dd, ref ee, aa, bb, messageBlock[5], 7);
            RightRound3(ref bb, cc, ref dd, ee, aa, messageBlock[1], 15);
            RightRound3(ref aa, bb, ref cc, dd, ee, messageBlock[3], 11);
            RightRound3(ref ee, aa, ref bb, cc, dd, messageBlock[7], 8);
            RightRound3(ref dd, ee, ref aa, bb, cc, messageBlock[14], 6);
            RightRound3(ref cc, dd, ref ee, aa, bb, messageBlock[6], 6);
            RightRound3(ref bb, cc, ref dd, ee, aa, messageBlock[9], 14);
            RightRound3(ref aa, bb, ref cc, dd, ee, messageBlock[11], 12);
            RightRound3(ref ee, aa, ref bb, cc, dd, messageBlock[8], 13);
            RightRound3(ref dd, ee, ref aa, bb, cc, messageBlock[12], 5);
            RightRound3(ref cc, dd, ref ee, aa, bb, messageBlock[2], 14);
            RightRound3(ref bb, cc, ref dd, ee, aa, messageBlock[10], 13);
            RightRound3(ref aa, bb, ref cc, dd, ee, messageBlock[0], 13);
            RightRound3(ref ee, aa, ref bb, cc, dd, messageBlock[4], 7);
            RightRound3(ref dd, ee, ref aa, bb, cc, messageBlock[13], 5);

            /* parallel round 4 */
            RightRound4(ref cc, dd, ref ee, aa, bb, messageBlock[8], 15);
            RightRound4(ref bb, cc, ref dd, ee, aa, messageBlock[6], 5);
            RightRound4(ref aa, bb, ref cc, dd, ee, messageBlock[4], 8);
            RightRound4(ref ee, aa, ref bb, cc, dd, messageBlock[1], 11);
            RightRound4(ref dd, ee, ref aa, bb, cc, messageBlock[3], 14);
            RightRound4(ref cc, dd, ref ee, aa, bb, messageBlock[11], 14);
            RightRound4(ref bb, cc, ref dd, ee, aa, messageBlock[15], 6);
            RightRound4(ref aa, bb, ref cc, dd, ee, messageBlock[0], 14);
            RightRound4(ref ee, aa, ref bb, cc, dd, messageBlock[5], 6);
            RightRound4(ref dd, ee, ref aa, bb, cc, messageBlock[12], 9);
            RightRound4(ref cc, dd, ref ee, aa, bb, messageBlock[2], 12);
            RightRound4(ref bb, cc, ref dd, ee, aa, messageBlock[13], 9);
            RightRound4(ref aa, bb, ref cc, dd, ee, messageBlock[9], 12);
            RightRound4(ref ee, aa, ref bb, cc, dd, messageBlock[7], 5);
            RightRound4(ref dd, ee, ref aa, bb, cc, messageBlock[10], 15);
            RightRound4(ref cc, dd, ref ee, aa, bb, messageBlock[14], 8);

            /* parallel round 5 */
            RightRound5(ref bb, cc, ref dd, ee, aa, messageBlock[12], 8);
            RightRound5(ref aa, bb, ref cc, dd, ee, messageBlock[15], 5);
            RightRound5(ref ee, aa, ref bb, cc, dd, messageBlock[10], 12);
            RightRound5(ref dd, ee, ref aa, bb, cc, messageBlock[4], 9);
            RightRound5(ref cc, dd, ref ee, aa, bb, messageBlock[1], 12);
            RightRound5(ref bb, cc, ref dd, ee, aa, messageBlock[5], 5);
            RightRound5(ref aa, bb, ref cc, dd, ee, messageBlock[8], 14);
            RightRound5(ref ee, aa, ref bb, cc, dd, messageBlock[7], 6);
            RightRound5(ref dd, ee, ref aa, bb, cc, messageBlock[6], 8);
            RightRound5(ref cc, dd, ref ee, aa, bb, messageBlock[2], 13);
            RightRound5(ref bb, cc, ref dd, ee, aa, messageBlock[13], 6);
            RightRound5(ref aa, bb, ref cc, dd, ee, messageBlock[14], 5);
            RightRound5(ref ee, aa, ref bb, cc, dd, messageBlock[0], 15);
            RightRound5(ref dd, ee, ref aa, bb, cc, messageBlock[3], 13);
            RightRound5(ref cc, dd, ref ee, aa, bb, messageBlock[9], 11);
            RightRound5(ref bb, cc, ref dd, ee, aa, messageBlock[11], 11);

            var nextHash = new uint[MessageSize / 32];
            nextHash[0] = previousHash[1] + c + dd;
            nextHash[1] = previousHash[2] + d + ee;
            nextHash[2] = previousHash[3] + e + aa;
            nextHash[3] = previousHash[4] + a + bb;
            nextHash[4] = previousHash[0] + b + cc;

            return nextHash;
        }

        /// <summary>
        /// Process the last message block.
        /// </summary>
        /// <remarks>
        /// Depending on the lenghts of last block, it may expand to one additional block.
        /// Last block is padded with 0's and lenght is appended.
        /// </remarks>
        /// <param name="resultBuffer">The result buffer.</param>
        /// <param name="lastMessageBlock">The message block.</param>
        /// <param name="lswlen">The lswlen.</param>
        private static void ProcessLastBlock(ref uint[] resultBuffer, byte[] lastMessageBlock, uint lswlen)
        {
            // puts bytes from lastMessageBlock into message and pad out; appends length
            // and finally, compresses the last block(s)
            // note: length in bits == 8 * (lswlen + 2^32 mswlen).
            // note: there are (lswlen mod 64) bytes left in unhashedBuffer.

            // initiallize message block with 0's
            var messageBlock = Enumerable.Repeat(0U, 16).ToArray();

            /* put bytes from lastMessageBlock into messageBlock */
            for (var i = 0; i < (lswlen & 63); i++)
            {
                /* byte i goes into word X[i div 4] at pos.  8*(i mod 4)  */
                messageBlock[i >> 2] ^= Convert.ToUInt32(lastMessageBlock[i]) << (8 * (i & 3));
            }

            /* append the bit m_n == 1 */
            messageBlock[(lswlen >> 2) & 15] ^= 1U << Convert.ToInt32((8 * (lswlen & 3)) + 7);

            if ((lswlen & 63) > 55)
            {
                /* length goes to next block */
                resultBuffer = ProcessBlock(resultBuffer, messageBlock);
                messageBlock = Enumerable.Repeat(0U, 16).ToArray();
            }

            /* append length in bits*/
            messageBlock[14] = lswlen << 3;
            messageBlock[15] = (lswlen >> 29) | (0 << 3);
            resultBuffer = ProcessBlock(resultBuffer, messageBlock);
        }
    }
}