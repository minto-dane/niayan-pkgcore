-- SPDX-License-Identifier: MIT
package body Pkg_Recovery_Catalog with SPARK_Mode is
   function Admissible(P : Policy; Item : Point) return Boolean is
     (P.Root_ID/=Zero_Identity and then P.Maximum_Test_Age>0 and then not P.Allow_Data_Downgrade
      and then Item.Root_ID=P.Root_ID and then Item.ID/=Zero_Identity
      and then Item.Manifest/=Zero_Digest and then Item.Package_Set/=Zero_Digest
      and then Item.Authenticated and then Item.Artifacts_Present and then Item.Integrity_Checked
      and then Item.Restoration_Tested and then not Item.Signing_Key_Revoked and then not Item.Vulnerable_Disallowed
      and then Item.Trust_Epoch>=P.Oldest_Trust_Epoch and then Item.Data_Schema=P.Current_Data_Schema
      and then Item.Created_At<=Item.Verified_At and then Item.Verified_At<=P.Now
      and then P.Now-Item.Verified_At<=P.Maximum_Test_Age);
   function Valid_Set(Items : Points; Count : Natural) return Boolean is
   begin
      if Count=0 or else Count>Max_Points then return False; end if;
      for I in 1..Count loop
         if Items(I).ID=Zero_Identity then return False; end if;
         for J in 1..I-1 loop if Items(I).ID=Items(J).ID then return False; end if; end loop;
      end loop;
      return True;
   end;
   procedure Select_Point(P : Policy; Items : Points; Count : Natural;
      Selected : out Natural; Status : out Outcome) is
   begin
      Selected:=0; Status:=Invalid_Input;
      if not Valid_Set(Items,Count) then return; end if;
      for I in 1..Count loop
         if Admissible(P,Items(I)) and then not Items(I).Unresolved_Intent
           and then (Selected=0 or else Items(I).Generation>Items(Selected).Generation)
         then Selected:=I; end if;
      end loop;
      Status:=(if Selected=0 then Denied else OK);
   end;
   function May_Prune(P : Policy; Items : Points; Count,Index : Natural) return Boolean is
      Remaining : Natural:=0;
   begin
      if not Valid_Set(Items,Count) or else Index=0 or else Index>Count then return False; end if;
      if Items(Index).Root_ID/=P.Root_ID or else Items(Index).Active or else Items(Index).Last_Accepted
        or else Items(Index).Unresolved_Intent or else Items(Index).Pinned_By_Operator
        or else Items(Index).Created_At>P.Now or else P.Now-Items(Index).Created_At<P.Minimum_Age then return False; end if;
      for I in 1..Count loop
         if I/=Index and then Admissible(P,Items(I)) and then not Items(I).Unresolved_Intent
         then Remaining:=Remaining+1; end if;
      end loop;
      return Remaining>=P.Minimum_Retained;
   end;
end Pkg_Recovery_Catalog;
