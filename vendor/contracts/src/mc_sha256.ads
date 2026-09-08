-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_SHA256 with SPARK_Mode, Pure is
   use type Wide;
   type Context is private;
   function Length (C : Context) return Wide with Global => null;
   function Initialize return Context with Global => null,
     Post => Length(Initialize'Result)=0;
   procedure Update (C : in out Context; Data : Bytes)
     with Global => null,
          Pre => Data'Length <= 16#7FFF_FFFF#
                 and then Length (C) <= 16#1FFF_FFFF_FFFF_FFFF# - Wide (Data'Length),
          Post => Length(C)=Length(C)'Old+Wide(Data'Length);
   function Finish (C : Context) return Digest with Global => null,
     Pre => Length (C) <= 16#1FFF_FFFF_FFFF_FF00#;
   function Hash (Data : Bytes) return Digest with Global => null,
     Pre => Data'Length <= 16#7FFF_FFFF#;
private
   type Words is array (Natural range <>) of Word;
   type Context is record
      State : Words (0 .. 7) :=
        (16#6A09E667#, 16#BB67AE85#, 16#3C6EF372#, 16#A54FF53A#,
         16#510E527F#, 16#9B05688C#, 16#1F83D9AB#, 16#5BE0CD19#);
      Block_Data : Bytes (1 .. 64) := (others => 0);
      Used : Natural range 0 .. 63 := 0;
      Total : Wide := 0;
   end record;
end MC_SHA256;
