-- SPDX-License-Identifier: BSD-3-Clause
with MC_Authentic;with MC_Contract_Profile;
package body MC_Config_Auth with SPARK_Mode=>Off is
   procedure Verify(A : Authority;C : Certificate;Expected : MC_Config_Receipt.Subject;
      Now,Minimum_Sequence : Counter;R : out MC_Config_Receipt.Receipt;Status : out Outcome) is
      V : MC_Config_Receipt.Receipt;
   begin
      R:=(others=><>);Status:=Denied;
      if A.Validator_Key=Bytes'(1..32=>0) or else A.Reviewer_Key=Bytes'(1..32=>0) or else
        A.Validator_Key=A.Reviewer_Key or else A.Validator_Domain=Zero_Identity or else
        A.Reviewer_Domain=Zero_Identity or else A.Validator_Domain=A.Reviewer_Domain or else
        A.Policy=Zero_Digest or else A.Policy/=Expected.Policy or else Expected.Contract/=MC_Contract_Profile.Fingerprint then return;end if;
      MC_Authentic.Verify("MissionCore/config-approval/v1/validator",C(1..512),C(513..576),A.Validator_Key,Status);
      if Status/=OK then return;end if;
      MC_Authentic.Verify("MissionCore/config-approval/v1/reviewer",C(1..512),C(577..640),A.Reviewer_Key,Status);
      if Status/=OK then return;end if;
      MC_Config_Receipt.Decode(C(1..512),V,Status);if Status/=OK then return;end if;
      MC_Config_Receipt.Check(V,Expected,Now,Minimum_Sequence,A.Max_Age,A.Max_Lifetime,Status);
      if Status=OK then R:=V;end if;
   end Verify;
end MC_Config_Auth;
