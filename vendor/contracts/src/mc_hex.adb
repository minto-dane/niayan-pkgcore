-- SPDX-License-Identifier: MIT
package body MC_Hex with SPARK_Mode is
   Table : constant String := "0123456789abcdef";
   function Encode (Data : Bytes) return String is
      Result : String (1 .. Data'Length * 2);
      K : Natural := 0;
   begin
      for Item of Data loop
         Result (K + 1) := Table (Natural (Item) / 16 + 1);
         Result (K + 2) := Table (Natural (Item) mod 16 + 1);
         K := K + 2;
      end loop;
      return Result;
   end Encode;
   function Nibble (C : Character) return Integer is
   begin
      if C in '0' .. '9' then return Character'Pos(C)-Character'Pos('0'); end if;
      if C in 'a' .. 'f' then return Character'Pos(C)-Character'Pos('a')+10; end if;
      return -1; -- Uppercase is deliberately non-canonical.
   end Nibble;
   procedure Decode (Text : String; Data : out Bytes; Status : out Outcome) is
      A,B : Integer;
      K : Natural := 0;
   begin
      Data := (others => 0); Status := Invalid_Input;
      if Data'Length > Integer'Last / 2 or else Text'Length /= Data'Length * 2 then
         return;
      end if;
      for J in Data'Range loop
         A := Nibble (Text (Text'First + K));
         B := Nibble (Text (Text'First + K + 1));
         if A < 0 or else B < 0 then Data := (others => 0); return; end if;
         Data (J) := Byte (A * 16 + B);
         K := K + 2;
      end loop;
      Status := OK;
   end Decode;
end MC_Hex;
