-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types;use MC_Types;with MC_Config_Receipt;with MC_Signatures;
package MC_Config_Auth with SPARK_Mode=>Off is
   Certificate_Size : constant:=640;
   subtype Certificate is Bytes(1..Certificate_Size);
   type Authority is record
      Validator_Key,Reviewer_Key : MC_Signatures.Public_Key:=(others=>0);
      Validator_Domain,Reviewer_Domain : Identity:=Zero_Identity;
      Policy : Digest:=Zero_Digest;
      Max_Age,Max_Lifetime : Counter:=0;
   end record;
   procedure Verify(A : Authority;C : Certificate;Expected : MC_Config_Receipt.Subject;
      Now,Minimum_Sequence : Counter;R : out MC_Config_Receipt.Receipt;Status : out Outcome);
   -- Authority is loaded from authenticated local policy, never from C itself.
   -- Distinct keys/domains, exact implementation profile, fixed role domains.
end MC_Config_Auth;
