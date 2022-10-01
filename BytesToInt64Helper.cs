using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Minidump
{
    internal class BytesToInt64Helper
    {
        const string formatter = "{0,5}{1,27}{2,24}";

        // Convert eight byte array elements to a long and display it.
        public static long BAToInt64(byte[] bytes, int index)
        {
            long value = BitConverter.ToInt64(bytes, index);

            Console.WriteLine(formatter, index,
                BitConverter.ToString(bytes, index, 8), value);
            return value;
        }

        // Display a byte array, using multiple lines if necessary.
        public static void WriteMultiLineByteArray(byte[] bytes)
        {
            const int rowSize = 20;
            int iter;

            Console.WriteLine("initial byte array");
            Console.WriteLine("------------------");

            for (iter = 0; iter < bytes.Length - rowSize; iter += rowSize)
            {
                Console.Write(
                    BitConverter.ToString(bytes, iter, rowSize));
                Console.WriteLine("-");
            }

            Console.WriteLine(BitConverter.ToString(bytes, iter));
            Console.WriteLine();
        }
    }
}
