using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Feistel
{
    public class FeistelCipher
    {
        byte[] _key;
        int _blockSize;
        FeistelType _feistelType;
        CipherMode _cipherMode;
        byte[] _IVcbc;
        byte[] _IVcfb;

        IEnumerable<byte[]> _keys
        {
            get
            {
                int i;
                for (i = 0; i < 4; i++)
                {
                    yield return CycleShift(_key, (byte)(i * 7), Direction.Right);
                }
            }
        }

        IEnumerable<byte[]> _keysReverse => _keys.Reverse();

        public FeistelCipher (int keySize, FeistelType feistelType, CipherMode cipherMode)
        {
            _feistelType = feistelType;
            _cipherMode = cipherMode;
            _key = GenerateKey(keySize);
            _blockSize = _key.Length * ((feistelType == FeistelType.ClassicFeistel) ? 2 : 4);
            if(cipherMode == CipherMode.CBC)
            {
                _IVcbc = GenerateIV(_blockSize);
            }
            if(cipherMode == CipherMode.CFB)
            {
                _IVcfb = GenerateIV(_blockSize);
            }
        }

        public FeistelCipher(byte[] key, FeistelType feistelType, CipherMode cipherMode):this(key.Length, feistelType, cipherMode)
        {
            if(key.Length % 2 != 0)
            {
                throw new Exception("Key size must be multiple of 2 size!");
            }
            _key = key;
            _blockSize = key.Length * ((feistelType == FeistelType.ClassicFeistel) ? 2 : 4);
            if (cipherMode == CipherMode.CBC)
            {
                _IVcbc = GenerateIV(_blockSize);
            }
            if (cipherMode == CipherMode.CFB)
            {
                _IVcfb = GenerateIV(_blockSize * 4);
            }
        }

        public string CryptText(string plainText, CryptType cryptType)
        {
            while (plainText.Length % _blockSize != 0)
                plainText += new char();

            var roundKeys = (_cipherMode == CipherMode.CFB) ? _keys : (cryptType == CryptType.Encrypt) ? _keys : _keysReverse;

            var plainTextBytes = Encoding.Default.GetBytes(plainText);

            byte[] iv = new byte[_blockSize];
            byte[] ivNew = new byte[_blockSize];

            if (_cipherMode == CipherMode.CBC)
            {
                iv = _IVcbc;
            }
            else if(_cipherMode == CipherMode.CFB)
            {
                iv = _IVcfb;
            }

            var result = "";
            var blockPosition = 0;

            while (blockPosition < plainTextBytes.Length)
            {
                var blockBytes = new byte[_blockSize];
                Array.Copy(plainTextBytes, blockPosition, blockBytes, 0, _blockSize);
                if (_cipherMode == CipherMode.None)
                    blockBytes = CryptBlock(blockBytes, roundKeys, cryptType);
                else if (_cipherMode == CipherMode.CBC)
                    blockBytes = CryptBlockCBC(blockBytes, ref iv, ref ivNew, roundKeys, cryptType);
                else if (_cipherMode == CipherMode.CFB)
                    blockBytes = CryptBlockCFB(blockBytes, ref iv, roundKeys, cryptType);
                else
                    throw new Exception("Undefined cipher mode");

                result += Encoding.Default.GetString(blockBytes);
                blockPosition += _blockSize;
            }
            return result.Trim('\0');
        }

        private byte[] CryptBlock(byte[] blockBytes, IEnumerable<byte[]> roundKeys, CryptType cryptType)
        {
            foreach (var key in roundKeys)
            {
                if (_feistelType == FeistelType.ClassicFeistel)
                    blockBytes = PerformEncryptionClassic(blockBytes, key, key.SequenceEqual(roundKeys.Last()));
                else
                    blockBytes = PerformEncryptionVariant1(blockBytes, key, cryptType);
            }
            return blockBytes;
        }

        private byte[] CryptBlockCBC(byte[] blockBytes, ref byte[] iv, ref byte[] ivNew, IEnumerable<byte[]> roundKeys, CryptType cryptType)
        {
            if (cryptType == CryptType.Encrypt)
                blockBytes = XOR(blockBytes, iv);
            else
                Array.Copy(blockBytes, ivNew, blockBytes.Length);
            foreach (var key in roundKeys)
            {
                if (_feistelType == FeistelType.ClassicFeistel)
                    blockBytes = PerformEncryptionClassic(blockBytes, key, key.SequenceEqual(roundKeys.Last()));
                else
                    blockBytes = PerformEncryptionVariant1(blockBytes, key, cryptType);
            }
            if (cryptType == CryptType.Encrypt)
                iv = blockBytes;
            else
            {
                blockBytes = XOR(blockBytes, iv);
                Array.Copy(ivNew, iv, ivNew.Length);
            }
            return blockBytes;
        }

        private byte[] CryptBlockCFB(byte[] blockBytes, ref byte[] iv, IEnumerable<byte[]> roundKeys, CryptType cryptType)
        {
            var tempCipher = new byte[blockBytes.Length];
            Array.Copy(blockBytes, tempCipher, blockBytes.Length);
            foreach(var key in roundKeys)
            {
                if (_feistelType == FeistelType.ClassicFeistel)
                    iv = PerformEncryptionClassic(iv, key, key.SequenceEqual(roundKeys.Last()));
                else
                    iv = PerformEncryptionVariant1(iv, key, CryptType.Encrypt);
            }
            var result = XOR(iv, blockBytes);
            Array.Copy((cryptType == CryptType.Encrypt) ? result : tempCipher, iv, result.Length);
            return result;
        }

        private byte[] PerformEncryptionClassic(byte[] blockBytes, byte[] roundKey, bool lastRound)
        {
            var leftBlock = new byte[blockBytes.Length / 2];
            var rightBlock = new byte[blockBytes.Length / 2];

            Array.Copy(blockBytes, leftBlock, leftBlock.Length);
            Array.Copy(blockBytes, leftBlock.Length, rightBlock, 0, rightBlock.Length);

            var rightBlockNew = ApplyRoundFunction(leftBlock, roundKey);

            for (uint rightBlockNo = 0; rightBlockNo < leftBlock.Length; ++rightBlockNo)
            {
                rightBlockNew[rightBlockNo] ^= rightBlock[rightBlockNo];
            }

            byte[] resultBlockBytes = new byte[blockBytes.Length];

            if (!lastRound)
            {
                Array.Copy(rightBlockNew, resultBlockBytes, rightBlockNew.Length);
                Array.Copy(leftBlock, 0, resultBlockBytes, leftBlock.Length, rightBlockNew.Length);
            }
            else
            {
                Array.Copy(leftBlock, resultBlockBytes, leftBlock.Length);
                Array.Copy(rightBlockNew, 0, resultBlockBytes, leftBlock.Length, rightBlockNew.Length);
            }
            return resultBlockBytes;
        }

        private byte[] PerformEncryptionVariant1(byte[] block, byte[] roundKey, CryptType cryptType)
        {
            var q1 = new byte[block.Length / 4];
            var q2 = new byte[block.Length / 4];
            var q3 = new byte[block.Length / 4];
            var q4 = new byte[block.Length / 4];

            Array.Copy(block, q1, q1.Length);
            Array.Copy(block, q1.Length, q2, 0, q2.Length);
            Array.Copy(block, q1.Length + q2.Length, q3, 0, q3.Length);
            Array.Copy(block, q1.Length + q2.Length + q3.Length, q4, 0, q4.Length);

            var q2new = new byte[q2.Length];
            if (cryptType == CryptType.Encrypt)
            {
                q2new = ApplyRoundFunction(q1, roundKey);
                q2new = XOR(q2new, q2);
            }
            else
            {
                q2new = ApplyRoundFunction(q4, roundKey);
                q2new = XOR(q2new, q1);
            }

            var result = new byte[block.Length];

            if (cryptType == CryptType.Encrypt)
            {
                Array.Copy(q2new, result, q2new.Length);
                Array.Copy(q3, 0, result, q2new.Length, q3.Length);
                Array.Copy(q4, 0, result, q2new.Length + q3.Length, q4.Length);
                Array.Copy(q1, 0, result, q2new.Length + q3.Length + q4.Length, q1.Length);
            }
            else
            {
                Array.Copy(q4, result, q4.Length);
                Array.Copy(q2new, 0, result, q4.Length, q2new.Length);
                Array.Copy(q2, 0, result, q4.Length + q2new.Length, q2.Length);
                Array.Copy(q3, 0, result, q4.Length + q1.Length + q2new.Length, q3.Length);
            }
            return result;
        }

        private byte[] ApplyRoundFunction(byte[] blockBytes, byte[] roundKey)
        {
            return XOR(CycleShift(blockBytes, 9, Direction.Left), Inverse(MultiplicationMod2(CycleShift(roundKey, 11, Direction.Right), blockBytes)));
        }

        private byte[] MultiplicationMod2(byte[] array1, byte[] array2)
        {
            var result = new byte[array1.Length];
            for(uint i = 0; i < result.Length; i++)
            {
                result[i] = (byte)((array1[i] + array2[i]) % (Math.Pow(2, _blockSize) + 1));
            }
            return result;
        }

        private byte[] XOR(byte[] array1, byte[] array2)
        {
            var result = new byte[array1.Length];
            for(uint i = 0; i < result.Length; i++)
            {
                result[i] = (byte)(array1[i] ^ array2[i]);
            }
            return result;
        }

        private byte[] Inverse(byte[] array)
        {
            var result = new byte[array.Length];
            for(uint i = 0; i < result.Length; i++)
            {
                result[i] = (byte)~array[i];
            }
            return result;
        }

        private byte[] Shift(byte[] array, byte count, Direction direction)
        {
            var result = new byte[array.Length];
            Array.Copy(array, result, array.Length);
            while(count > 0)
            {
                result = PerformShift(result, direction);
                count--;
            }
            return result;
        }

        private byte[] PerformShift(byte[] array, Direction direction)
        {
            var result = new byte[array.Length];
            Array.Copy(array, result, array.Length);
            if(direction == Direction.Left)
            {
                var tempByte = false;
                bool newTempByte;
                for(int i = result.Length - 1; i >= 0; i--)
                {
                    newTempByte = GetBit(result[i], 7);
                    result[i] = (byte)(result[i] << 1);
                    SetBit(tempByte, ref result[i], 0);
                    tempByte = newTempByte;
                }
            }
            else
            {
                var tempByte = false;
                bool newTempByte;
                for(int i = 0; i < result.Length; i++)
                {
                    newTempByte = GetBit(result[i], 0);
                    result[i] = (byte)(result[i] >> 1);
                    SetBit(tempByte, ref result[i], 7);
                    tempByte = newTempByte;
                }
            }
            return result;
        }

        private byte[] CycleShift(byte[] array, byte count, Direction direction)
        {
            count %= (byte)(array.Length * 8);
            var result = new byte[array.Length];
            Array.Copy(array, result, array.Length);
            while(count > 8)
            {
                result = PerformCycleShift(result, 8, direction);
                count -= 8;
            }
            result = PerformCycleShift(result, count, direction);
            return result;
        }

        private byte[] PerformCycleShift(byte[] array, byte count, Direction direction)
        {
                bool[] tempBits;
                bool[] newTempBits;
                if (direction == Direction.Left)
                {
                    tempBits = SaveBits(array[0], count, direction);
                    for (int i = array.Length - 1; i >= 0; i--)
                    {
                        newTempBits = SaveBits(array[i], count, direction);
                        array[i] = (byte)(array[i] << count);
                        PutBits(ref array[i], tempBits, direction);
                        tempBits = newTempBits;
                    }
                }
                else
                {
                    tempBits = SaveBits(array[array.Length - 1], count, direction);
                    for (int i = 0; i < array.Length; i++)
                    {
                        newTempBits = SaveBits(array[i], count, direction);
                        array[i] = (byte)(array[i] >> count);
                        PutBits(ref array[i], tempBits, direction);
                        tempBits = newTempBits;
                    }
                }
                return array;
        }

        private void PutBits(ref byte currentByte, bool[] savedBits, Direction direction)
        {
            if (direction == Direction.Left)
            {
                Array.Reverse(savedBits);
                for (int i = 0; i < savedBits.Length; i++)
                {
                    SetBit(savedBits[i], ref currentByte, i);
                }
            }
            else
            {
                Array.Reverse(savedBits);
                for (int i = savedBits.Length - 1; i >= 0; i--)
                {
                    SetBit(savedBits[i], ref currentByte, 7 - i);
                }
            }
        }

        private bool[] SaveBits(byte currentByte, byte count, Direction direction)
        {
            var tempArray = new bool[count];
            for (uint i = 0; i < count; i++)
                tempArray[i] = GetBit(currentByte, (direction == Direction.Left) ? (7 - i) : i);
            return tempArray;
        }

        private bool GetBit(byte value, uint index)
        {
            if (index > 8)
                throw new Exception("index must be < 8");
            return ((value & (1 << (int)index)) != 0) ? true : false;
        }

        private void SetBit(bool bitValue, ref byte container, int index)
        {
            container = (byte)((bitValue) ?
                container | (1 << index) :
                container & (~(1 << index)));
        }

        private byte[] GenerateIV(int size)
        {
            var result = new byte[size];
            var random = new Random();
            random.NextBytes(result);
            return result;
        }

        private byte[] GenerateKey(int size)
        {
            var result = new byte[size];
            var random = new Random();
            random.NextBytes(result);
            return result;
        }

        private byte[] GetBits(byte[] array, uint count, Direction direction)
        {
            if(count > array.Length)
            {
                throw new Exception("count must be less that length of array");
            }
            var result = new byte[count];
            for (uint i = 0; i < result.Length; i++)
                if (direction == Direction.Left)
                    result[i] = array[i];
                else
                    result[i] = array[array.Length-count + i];
            return result;
        }

        private byte[] ConcatBits(byte[] array1, byte[] array2)
        {
            var result = new byte[array1.Length + array2.Length];
            Array.Copy(array1, result, array1.Length);
            Array.Copy(array2, 0, result, array1.Length, array2.Length);
            return result;
        }
    }
}
