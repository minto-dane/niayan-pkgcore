-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Hex with SPARK_Mode, Pure is
   function Encode (Data : Bytes) return String
     with Global => null, Pre => Data'Length <= Integer'Last / 2,
       Post => Encode'Result'First=1 and then Encode'Result'Length=2*Data'Length;
   procedure Decode (Text : String; Data : out Bytes; Status : out Outcome)
     with Global => null;
end MC_Hex;
