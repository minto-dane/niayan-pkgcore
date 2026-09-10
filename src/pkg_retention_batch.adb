-- SPDX-License-Identifier: BSD-3-Clause
package body Pkg_Retention_Batch with SPARK_Mode is
   procedure Plan (P : Policy; C : MC_Backups.Catalog; Count : Natural;
      Requested : MC_Backups.Selection; Delete_Set : out MC_Backups.Selection;
      Status : out Outcome) is
      Members : MC_Backups.Selection; S : Outcome;
      D : Digest; Remaining : Natural := 0; Blocked, New_Position : Boolean;
      Accepted : MC_Backups.Selection := (others => False);
      First_Time : Counter := Counter'Last; Last_Time : Counter := 0;
      Representative_Time : Counter;
   begin
      Delete_Set := (others => False); Status := Denied;
      if not MC_Backups.Valid (P.Recovery) or else not MC_Backups.Valid_Catalog (C,Count)
        or else P.Catalog_Revision = 0 or else P.Reference_Revision = 0
        or else not P.Complete_Reference_Scan or else not P.Writers_Quiescent
        or else not P.Audit_Export_Confirmed then return; end if;
      -- Authentication must also cover objects proposed for deletion, not only
      -- the restore points that survive. Never trust an unsigned "no legal hold"
      -- flag or an expired location receipt to authorize erasure.
      for I in 1..Count loop
         if not C (I).Authenticated or else not C (I).Header_Payload_Bound then return; end if;
      end loop;
      for I in MC_Backups.Index loop
         if Requested (I) then
            if I > Count then return; end if;
            if C (I).Scope /= P.Recovery.Scope or else C (I).Dataset /= P.Recovery.Dataset
              or else C (I).Lineage /= P.Recovery.Lineage or else C (I).Pinned
              or else C (I).In_Use or else C (I).Legal_Hold
              or else C (I).Retain_Until > P.Recovery.Now_Lower
              or else C (I).Completed_At > P.Recovery.Now_Lower
              or else P.Recovery.Now_Lower-C (I).Completed_At < P.Minimum_Age
            then return; end if;
            for Copy of C (I).Locations loop
               if Copy.Store_ID /= Zero_Identity and then
                 (not Copy.Authenticated or else Copy.Receipt_Hash = Zero_Digest
                  or else Copy.Object_Hash /= C (I).Payload
                  or else Copy.Valid_Until <= P.Recovery.Now_Upper)
               then return; end if;
               if Copy.Immutable_Until > P.Recovery.Now_Lower then return; end if;
            end loop;
         end if;
      end loop;
      for I in 1..Count loop
         pragma Loop_Invariant(Remaining<=I-1);
         if not Requested (I) then
            MC_Backups.Chain (C,Count,I,Members,D,S);
            if S /= OK then return; end if;
            for J in 1..Count loop
               if Members (J) and then Requested (J) then return; end if;
            end loop;
            MC_Backups.Restore_Set (P.Recovery,C,Count,I,Members,S);
            if S = OK and then C (I).Restore_Test_Chain = D then
               Blocked := False;
               for J in 1..Count loop
                  Blocked := Blocked or else (Members (J) and then Requested (J));
               end loop;
               if not Blocked then
                  New_Position := True;
                  for J in 1..I-1 loop
                     if Accepted (J) and then C (J).Through_Position = C (I).Through_Position
                     then New_Position := False; end if;
                  end loop;
                  Accepted (I) := True;
                  if New_Position then Remaining := Remaining+1; end if;
               end if;
            end if;
         end if;
      end loop;
      -- Measure the span once per distinct position, using its earliest
      -- retained, validated completion. Recopying an unchanged position must
      -- not manufacture a wider recovery history.
      for I in 1..Count loop
         if Accepted (I) then
            New_Position := True; Representative_Time := C (I).Completed_At;
            for J in 1..Count loop
               if Accepted (J) and then C (J).Through_Position = C (I).Through_Position then
                  if J < I then New_Position := False; end if;
                  Representative_Time := Counter'Min (Representative_Time,C (J).Completed_At);
               end if;
            end loop;
            if New_Position then
               First_Time := Counter'Min (First_Time,Representative_Time);
               Last_Time := Counter'Max (Last_Time,Representative_Time);
            end if;
         end if;
      end loop;
      if Remaining < P.Minimum_Restore_Points or else First_Time > Last_Time
        or else Last_Time - First_Time < P.Minimum_Recovery_Span then return; end if;
      Delete_Set := Requested; Status := OK;
   end Plan;
end Pkg_Retention_Batch;
