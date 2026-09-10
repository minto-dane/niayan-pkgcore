-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types; with MC_Release;
package MC_Qualification with SPARK_Mode, Pure is
   type Role is (Builder, Security_Reviewer, Operations_Approver);
   type Authority is record
      Key : Digest := Zero_Digest;
      Principal : Identity := Zero_Identity;
      Domain : Counter := 0;
      Duty : Role := Builder;
   end record;
   type Authority_List is array (Positive range 1 .. 16) of Authority;
   type Policy is record
      Source_Set, Binary_Set, Contract, Platform, Policy_ID : Digest := Zero_Digest;
      Trust_Epoch, Max_Lifetime : Counter := 0;
      Count : Natural range 0 .. 16 := 0;
      Keys : Authority_List;
   end record;
   type Claim is record
      Item : MC_Release.Evidence_Item := MC_Release.Compiler_Build;
      Result : MC_Release.Evidence_State := MC_Release.Missing;
      Issuer, Source_Set, Binary_Set, Contract, Platform, Report, Policy_ID : Digest := Zero_Digest;
      Not_Before, Expires, Trust_Epoch : Counter := 0;
   end record;
   type Claims is array (MC_Release.Evidence_Item) of Claim;
   type Signature_Results is array (MC_Release.Evidence_Item) of Boolean;
   type Assessment is record
      Eligible : Boolean := False;
      Invalid : Signature_Results := (others => True);
      Independent_Roles : Boolean := False;
   end record;
   subtype Frame is Bytes (1 .. 320);
   function Valid (P : Policy) return Boolean with Global => null;
   function Encode (C : Claim) return Frame with Global => null;
   procedure Decode (B : Bytes; C : out Claim; Status : out Outcome) with Global => null;
   function Evaluate (P : Policy; C : Claims; Verified : Signature_Results;
      Now : Counter) return Assessment with Global => null;
   -- All MC_Release evidence categories required. No "missing proof = passed".
   -- Independent build/review/operations principals and failure domains required.
   -- Verified must come from MC_Qualification_Auth (or an equivalent verifier),
   -- never an untrusted file. A valid signed report attests an issuer's claim,
   -- not truth of tests; report contents and qualification process need audit.
end MC_Qualification;
