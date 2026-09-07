-- SPDX-License-Identifier: MIT
with Interfaces;
package body MC_Codec with SPARK_Mode is
   use type Word; use type Wide;
   function U16 (Data : Bytes; At_Byte : Positive) return Natural is
     (Natural (Data (At_Byte)) * 256 + Natural (Data (At_Byte + 1)));
   function U32 (Data : Bytes; At_Byte : Positive) return Word is
      V : Word := 0;
   begin
      for J in 0 .. 3 loop
         V := Interfaces.Shift_Left (V, 8) or Word (Data (At_Byte + J));
      end loop;
      return V;
   end U32;
   function U64 (Data : Bytes; At_Byte : Positive) return Wide is
      V : Wide := 0;
   begin
      for J in 0 .. 7 loop
         V := Interfaces.Shift_Left (V, 8) or Wide (Data (At_Byte + J));
      end loop;
      return V;
   end U64;
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
