-- SPDX-License-Identifier: MIT
with MC_SHA256;
package body Pkg_File_Replay with SPARK_Mode is
   function Valid (B : Binding) return Boolean is
     (B.Root_ID /= Zero_Identity and then B.Transaction_ID /= Zero_Identity
      and then B.Plan_Digest /= Zero_Digest and then B.Epoch > 0
      and then B.Fence > 0 and then B.Target_Generation > 0 and then B.Changes > 0);

   function Valid (B : Binding; V : View) return Boolean is
   begin
      if not Valid (B) then return False; end if;
      if V.Records = 0 then
         return V.Phase = Forward and then V.Next_Index = 1
           and then V.Pending_Index = 0 and then V.Receipt = Zero_Digest
           and then V.Last_Digest = Zero_Digest;
      end if;
      if V.Last_Digest = Zero_Digest or else V.Next_Index > B.Changes + 1
        or else V.Pending_Index > B.Changes then return False; end if;
      case V.Phase is
         when Forward =>
            return V.Next_Index >= 1 and then V.Receipt = Zero_Digest
              and then (V.Pending_Index = 0 or else V.Pending_Index = V.Next_Index);
         when Ready_To_Commit =>
            return V.Next_Index = B.Changes + 1 and then V.Pending_Index = 0
              and then V.Receipt = Zero_Digest;
         when Commit_Pending | Forward_Final =>
            return V.Next_Index = B.Changes + 1 and then V.Pending_Index = 0
              and then V.Receipt /= Zero_Digest;
         when Reverse_Change =>
            return V.Next_Index <= B.Changes and then V.Receipt /= Zero_Digest
              and then (V.Pending_Index = 0 or else V.Pending_Index = V.Next_Index);
         when Reverse_Final =>
            return V.Next_Index = 0 and then V.Pending_Index = 0
              and then V.Receipt /= Zero_Digest;
      end case;
   end Valid;

   procedure Consume (B : Binding; E : MC_Log_Format.Log_Entry;
                      V : in out View; Status : out Outcome) is
      N : View := V;
   begin
      Status := Corrupt;
      if not Valid (B,V) then return; end if;
      if V.Records = Counter'Last then Status := Exhausted; return; end if;
      if E.Sequence /= V.Records + 1 or else E.Previous /= V.Last_Digest
        or else E.Root_ID /= B.Root_ID or else E.Operation_ID /= B.Transaction_ID
        or else E.Epoch /= B.Epoch or else E.Token /= B.Fence
        or else E.Generation /= B.Target_Generation or else E.Index > Counter (B.Changes)
        or else E.Result /= OK then return; end if;
      if V.Records = 0 then
         if E.Kind /= Prepared or else E.Index /= 0 or else E.Object /= B.Plan_Digest
         then return; end if;
      elsif V.Phase in Forward_Final | Reverse_Final then
         return;
      else
         case E.Kind is
            when Apply_Intent =>
               if V.Phase /= Forward or else E.Index = 0
                 or else E.Index /= Counter (V.Next_Index) or else E.Object /= B.Plan_Digest
               then return; end if;
               N.Pending_Index := Natural (E.Index);
            when Apply_Done =>
               if V.Phase /= Forward or else E.Index = 0
                 or else E.Index /= Counter (V.Pending_Index)
                 or else E.Index /= Counter (V.Next_Index) or else E.Object /= B.Plan_Digest
               then return; end if;
               N.Pending_Index := 0; N.Next_Index := V.Next_Index + 1;
            when Applied =>
               if V.Phase /= Forward or else V.Next_Index /= B.Changes + 1
                 or else V.Pending_Index /= 0 or else E.Index /= 0
                 or else E.Object /= B.Plan_Digest then return; end if;
               N.Phase := Ready_To_Commit;
            when Commit_Intent =>
               if V.Phase not in Ready_To_Commit | Commit_Pending or else E.Index /= 0
                 or else E.Object = Zero_Digest
                 or else (V.Phase = Commit_Pending and then E.Object /= V.Receipt)
               then return; end if;
               N.Phase := Commit_Pending; N.Receipt := E.Object;
            when Committed =>
               if V.Phase /= Commit_Pending or else E.Index /= 0 or else E.Object /= V.Receipt
               then return; end if;
               N.Phase := Forward_Final;
            when Restore_Intent =>
               if V.Phase in Commit_Pending | Forward_Final | Reverse_Final
                 or else E.Index = 0 or else E.Object = Zero_Digest then return; end if;
               if V.Phase = Reverse_Change then
                  if E.Index /= Counter (V.Next_Index) or else E.Object /= V.Receipt then return; end if;
               else
                  if E.Index /= Counter (B.Changes) then return; end if;
                  N.Phase := Reverse_Change; N.Next_Index := B.Changes;
               end if;
               N.Pending_Index := Natural (E.Index); N.Receipt := E.Object;
            when Restore_Done =>
               if V.Phase /= Reverse_Change or else E.Index = 0
                 or else E.Index /= Counter (V.Pending_Index)
                 or else E.Index /= Counter (V.Next_Index) or else E.Object /= V.Receipt
               then return; end if;
               N.Pending_Index := 0; N.Next_Index := V.Next_Index - 1;
            when Restored =>
               if V.Phase /= Reverse_Change or else V.Next_Index /= 0
                 or else V.Pending_Index /= 0 or else E.Index /= 0 or else E.Object /= V.Receipt
               then return; end if;
               N.Phase := Reverse_Final;
            when Tail_Repaired =>
               if E.Index /= 0 or else E.Object = Zero_Digest then return; end if;
            when others => return;
         end case;
      end if;
      N.Records := V.Records + 1;
      N.Last_Digest := MC_SHA256.Hash (MC_Log_Format.Encode (E));
      if not Valid (B,N) then return; end if;
      V := N; Status := OK;
   end Consume;

   function Image_Allowed (B : Binding; V : View; Index : Positive;
                           Matches_Before, Matches_After : Boolean) return Boolean is
   begin
      if not Valid (B,V) or else V.Records = 0 or else Index > B.Changes
        or else not (Matches_Before or Matches_After) then return False; end if;
      case V.Phase is
         when Forward =>
            if Index < V.Next_Index then return Matches_After;
            elsif Index = V.Pending_Index then return True;
            else return Matches_Before; end if;
         when Ready_To_Commit | Commit_Pending | Forward_Final => return Matches_After;
         when Reverse_Change =>
            if Index > V.Next_Index then return Matches_Before; else return True; end if;
         when Reverse_Final => return Matches_Before;
      end case;
   end Image_Allowed;
end Pkg_File_Replay;
