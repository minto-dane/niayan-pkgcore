-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types; with MC_Qualification; with MC_Release; with MC_Signatures;
package MC_Qualification_Auth with SPARK_Mode => Off is
   Domain : constant String := "MISSION-CORE-QUALIFICATION-v1";
   type Raw_Claims is array (MC_Release.Evidence_Item) of MC_Qualification.Frame;
   type Signatures is array (MC_Release.Evidence_Item) of MC_Signatures.Signature;
   procedure Verify (P : MC_Qualification.Policy; Raw : Raw_Claims; Sig : Signatures;
      Now : Counter; A : out MC_Qualification.Assessment; Status : out Outcome);
   -- P and Now are locally provisioned/scoped policy and trustworthy clock.
   -- Keys from Raw are selectors only; only matching P.Keys are trusted.
end MC_Qualification_Auth;
