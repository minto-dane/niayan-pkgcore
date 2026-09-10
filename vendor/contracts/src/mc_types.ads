-- SPDX-License-Identifier: BSD-3-Clause
with Interfaces;
package MC_Types with SPARK_Mode, Pure is
   subtype Byte is Interfaces.Unsigned_8;
   subtype Word is Interfaces.Unsigned_32;
   subtype Wide is Interfaces.Unsigned_64;
   type Bytes is array (Positive range <>) of Byte;
   for Bytes'Component_Size use 8;
   subtype Digest is Bytes (1 .. 32);
   subtype Identity is Bytes (1 .. 16);
   Zero_Digest : constant Digest := (others => 0);
   Zero_Identity : constant Identity := (others => 0);
   type Counter is range 0 .. 2 ** 63 - 1;
   subtype Nonzero_Counter is Counter range 1 .. Counter'Last;
   Max_Message : constant := 1_048_576;
   type Outcome is
     (OK, Invalid_Input, Unsupported, Denied, Conflict, Stale,
      Exhausted, IO_Error, Corrupt, Indeterminate, Not_Qualified);
   function Is_Zero (Value : Bytes) return Boolean
     with Global => null;
   function Same_Bytes (Left, Right : Bytes) return Boolean
     with Global => null;
end MC_Types;
