-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package MC_Codec with SPARK_Mode, Pure is
   use type MC_Types.Wide; use type MC_Types.Word;
   function U16 (Data : Bytes; At_Byte : Positive) return Natural
     with Pre => At_Byte in Data'Range and then Data'Last - At_Byte >= 1,
          Post => U16'Result <= 65_535, Global => null;
   function U32 (Data : Bytes; At_Byte : Positive) return Word
     with Pre => At_Byte in Data'Range and then Data'Last - At_Byte >= 3,
          Global => null;
   function U64 (Data : Bytes; At_Byte : Positive) return Wide
     with Pre => At_Byte in Data'Range and then Data'Last - At_Byte >= 7,
          Global => null;
   procedure Put16 (Data : in out Bytes; At_Byte : Positive; Value : Natural)
     with Pre => Value <= 65_535 and then At_Byte in Data'Range
            and then Data'Last - At_Byte >= 1,
          Post => U16 (Data, At_Byte) = Value, Global => null;
   procedure Put32 (Data : in out Bytes; At_Byte : Positive; Value : Word)
     with Pre => At_Byte in Data'Range and then Data'Last - At_Byte >= 3,
          Post => U32 (Data, At_Byte) = Value, Global => null;
   procedure Put64 (Data : in out Bytes; At_Byte : Positive; Value : Wide)
     with Pre => At_Byte in Data'Range and then Data'Last - At_Byte >= 7,
          Post => U64 (Data, At_Byte) = Value, Global => null;
end MC_Codec;
