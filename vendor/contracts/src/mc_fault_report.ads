-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Faults;
package MC_Fault_Report with SPARK_Mode, Pure is
   Record_Size : constant := 320;
   subtype Frame is Bytes (1 .. Record_Size);
   function Encode (F : MC_Faults.Fault) return Frame
     with Pre => MC_Faults.Valid (F), Global => null;
   procedure Decode (B : Bytes; F : out MC_Faults.Fault; Status : out Outcome)
     with Global => null;
end MC_Fault_Report;
