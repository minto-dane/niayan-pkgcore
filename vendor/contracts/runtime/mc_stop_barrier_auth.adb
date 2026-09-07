-- SPDX-License-Identifier: MIT
with MC_Authentic; with MC_Contract_Profile;
package body MC_Stop_Barrier_Auth with SPARK_Mode => Off is
   use type MC_Stop_Barrier.Channel;
   procedure Verify (P : MC_Stop_Barrier.Policy; Raw : Bytes;
      Signature : MC_Signatures.Signature; E : out MC_Stop_Barrier.Evidence;
      Status : out Outcome)
   is
      T : MC_Stop_Barrier.Evidence; K : Natural := 0; Key : Digest := Zero_Digest;
   begin
      E := (others => <>); Status := Denied;
      if not MC_Stop_Barrier.Valid (P) or else P.Contract /= MC_Contract_Profile.Fingerprint then return; end if;
      MC_Stop_Barrier.Decode (Raw,T,Status); if Status /= OK then return; end if;
      if T.Policy_Hash /= MC_Stop_Barrier.Fingerprint (P) then Status := Denied; return; end if;
      for I in 1..P.Count loop
         if T.Node_ID = P.Members (I).Node_ID and then T.Resource_ID = P.Members (I).Resource_ID
           and then T.Subject_Boot = P.Members (I).Boot_ID then K := I; end if;
      end loop;
      if K = 0 then Status := Denied; return; end if;
      Key := (if T.Source = MC_Stop_Barrier.Node_Agent then P.Members (K).Stop_Key else P.Members (K).Fence_Key);
      MC_Authentic.Verify (Domain,Raw,Signature,Key,Status);
      if Status = OK then E := T; end if;
   end Verify;
end MC_Stop_Barrier_Auth;
