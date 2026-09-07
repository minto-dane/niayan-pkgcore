-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Base64 with SPARK_Mode, Pure is
   function Encode(Data : Bytes) return String with Global=>null,Pre=>Data'Length<=1_048_576;
   procedure Decode(Text : String; Data : out Bytes; Used : out Natural; Status : out Outcome) with Global=>null;
   -- RFC 4648 canonical padded alphabet, zero pad bits, no whitespace/URL alphabet.
end MC_Base64;
