-- SPDX-License-Identifier: BSD-3-Clause
with MC_Authentic; with MC_Contract_Profile;
package body MC_Qualification_Auth with SPARK_Mode => Off is
   procedure Verify (P : MC_Qualification.Policy; Raw : Raw_Claims; Sig : Signatures;
      Now : Counter; A : out MC_Qualification.Assessment; Status : out Outcome) is
      C : MC_Qualification.Claims;
      V : MC_Qualification.Signature_Results := (others => False);
      Local : Outcome; Key : Digest;
   begin
      A := (others => <>); Status := Denied;
      if not MC_Qualification.Valid (P) or else P.Contract /= MC_Contract_Profile.Fingerprint then return; end if;
      for I in MC_Release.Evidence_Item loop
         MC_Qualification.Decode (Raw (I),C (I),Local);
         if Local = OK then
            Key := Zero_Digest;
            for K in 1 .. P.Count loop
               if C (I).Issuer = P.Keys (K).Key then Key := P.Keys (K).Key; end if;
            end loop;
            if Key /= Zero_Digest then
               MC_Authentic.Verify (Domain,Raw (I),Sig (I),Key,Local); V (I) := Local = OK;
            end if;
         end if;
      end loop;
      A := MC_Qualification.Evaluate (P,C,V,Now);
      Status := (if A.Eligible then OK else Denied);
   end Verify;
end MC_Qualification_Auth;
