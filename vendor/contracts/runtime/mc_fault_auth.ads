-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Faults; with MC_Signatures;
package MC_Fault_Auth with SPARK_Mode => Off is
   procedure Verify
     (Data : Bytes; Signature : MC_Signatures.Signature;
      Key : MC_Signatures.Public_Key; F : out MC_Faults.Fault; Status : out Outcome);
   -- Domain separation is fixed to MC-FAULT-v1. Key provisioning and source role
   -- are local policy; never select a verification key from the report itself.
end MC_Fault_Auth;
