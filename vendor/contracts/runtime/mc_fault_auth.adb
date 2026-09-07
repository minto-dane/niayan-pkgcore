-- SPDX-License-Identifier: MIT
with MC_Authentic; with MC_Fault_Report;
package body MC_Fault_Auth with SPARK_Mode => Off is
   procedure Verify
     (Data : Bytes; Signature : MC_Signatures.Signature;
      Key : MC_Signatures.Public_Key; F : out MC_Faults.Fault; Status : out Outcome) is
   begin
      F := (others => <>);
      MC_Authentic.Verify ("MC-FAULT-v1", Data, Signature, Key, Status);
      if Status = OK then MC_Fault_Report.Decode (Data, F, Status); end if;
   end Verify;
end MC_Fault_Auth;
