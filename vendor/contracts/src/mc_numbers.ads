-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Numbers with SPARK_Mode, Pure is
   procedure Parse(S : String; N : out Counter; Status : out Outcome) with Global=>null;
   function Image(N : Counter) return String with Global=>null;
end MC_Numbers;
