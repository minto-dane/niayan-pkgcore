-- SPDX-License-Identifier: BSD-3-Clause
with Interfaces;
package body MC_Codec with SPARK_Mode is
   use type Word; use type Wide;
   function U16 (Data : Bytes; At_Byte : Positive) return Natural is
     (Natural (Data (At_Byte)) * 256 + Natural (Data (At_Byte + 1)));
   function U32 (Data : Bytes; At_Byte : Positive) return Word is
     (Interfaces.Shift_Left (Word (Data (At_Byte)), 24)
      or Interfaces.Shift_Left (Word (Data (At_Byte + 1)), 16)
      or Interfaces.Shift_Left (Word (Data (At_Byte + 2)), 8)
      or Word (Data (At_Byte + 3)));
   function U64 (Data : Bytes; At_Byte : Positive) return Wide is
     (Interfaces.Shift_Left (Wide (Data (At_Byte)), 56)
      or Interfaces.Shift_Left (Wide (Data (At_Byte + 1)), 48)
      or Interfaces.Shift_Left (Wide (Data (At_Byte + 2)), 40)
      or Interfaces.Shift_Left (Wide (Data (At_Byte + 3)), 32)
      or Interfaces.Shift_Left (Wide (Data (At_Byte + 4)), 24)
      or Interfaces.Shift_Left (Wide (Data (At_Byte + 5)), 16)
      or Interfaces.Shift_Left (Wide (Data (At_Byte + 6)), 8)
      or Wide (Data (At_Byte + 7)));
   procedure Put16 (Data : in out Bytes; At_Byte : Positive; Value : Natural) is
   begin
      Data (At_Byte) := Byte (Value / 256);
      Data (At_Byte + 1) := Byte (Value mod 256);
   end Put16;
   procedure Put32 (Data : in out Bytes; At_Byte : Positive; Value : Word) is
   begin
      for J in 0 .. 3 loop
         Data (At_Byte + J) := Byte
           (Interfaces.Shift_Right (Value, (3 - J) * 8) and 16#FF#);
      end loop;
   end Put32;
   procedure Put64 (Data : in out Bytes; At_Byte : Positive; Value : Wide) is
   begin
      for J in 0 .. 7 loop
         Data (At_Byte + J) := Byte
           (Interfaces.Shift_Right (Value, (7 - J) * 8) and 16#FF#);
      end loop;
   end Put64;
end MC_Codec;
