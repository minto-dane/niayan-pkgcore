-- SPDX-License-Identifier: BSD-3-Clause
package body MC_Types with SPARK_Mode is
   use type Byte;
   function Is_Zero (Value : Bytes) return Boolean is
      Combined : Byte := 0;
   begin
      for Item of Value loop
         Combined := Combined or Item;
      end loop;
      return Combined = 0;
   end Is_Zero;

   function Same_Bytes (Left, Right : Bytes) return Boolean is
      Combined : Byte := 0;
   begin
      if Left'Length /= Right'Length then
         return False;
      end if;
      for J in 0 .. Left'Length - 1 loop
         Combined := Combined or
           (Left (Left'First + J) xor Right (Right'First + J));
      end loop;
      return Combined = 0;
      -- Source-level full-length comparison, not a constant-time machine-code claim.
   end Same_Bytes;
end MC_Types;
