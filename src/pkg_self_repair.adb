-- SPDX-License-Identifier: BSD-3-Clause
package body Pkg_Self_Repair with SPARK_Mode is
   use type Pkg_File_Plan.Kind; use type Pkg_File_Plan.State_Domain;
   procedure Build(P : Policy; C : Context; Baseline : Pkg_Inventory.Manifest;
      Observed : Finding_Array; Result : out Pkg_File_Plan.Plan;
      Changed, Blocked : out Natural; Status : out Outcome) is
      Needed : Counter:=0;
   begin
      Pkg_File_Plan.Clear(Result); Changed:=0; Blocked:=0; Status:=Denied;
      if not Pkg_Inventory.Valid(Baseline) or else P.Root_ID=Zero_Identity
        or else P.Inventory_Digest=Zero_Digest or else P.Maximum_Age_Ms=0 or else P.Maximum_Age_Ms>60_000
        or else P.Maximum_Bytes=0 or else P.Maximum_Bytes>8*1_024*1_024*1_024
        or else C.Root_ID/=P.Root_ID or else Baseline.Root_ID/=P.Root_ID
        or else Pkg_Inventory.Fingerprint(Baseline)/=P.Inventory_Digest
        or else C.Inventory_Digest/=P.Inventory_Digest or else C.Generation/=Baseline.Generation
        or else C.Generation=Counter'Last or else C.Epoch=0 or else C.Fence=0 or else C.Transaction_ID=Zero_Identity
        or else not MC_Time_Guard.Fresh(C.Stamp,C.Boot_ID,C.Now,P.Maximum_Age_Ms)
        or else not C.Authenticated_Baseline or else not C.Ownership_Exclusive or else not C.Quiesced
        or else not C.Capacity_Sufficient or else not C.Recovery_Artifacts_Verified
        or else C.Intrusion_Suspected or else C.Hardware_Fault_Suspected or else C.Pending_Change or else C.Maintenance
      then return; end if;
      for I in 1..Baseline.Count loop
         pragma Loop_Invariant(Changed<=I-1 and then Blocked<=I-1);
         if not Observed(I).Known or else not Pkg_File_Plan.Valid(Observed(I).Actual) then Blocked:=Blocked+1;
         elsif not Pkg_File_Plan.Equal(Observed(I).Actual,Baseline.Items(I).Desired) then
            Changed:=Changed+1;
            if not Baseline.Items(I).Allow_Automatic_Repair or else Baseline.Items(I).Boot_Or_Security_Critical
              or else Baseline.Items(I).Domain/=Pkg_File_Plan.Packaged_Files
              or else Baseline.Items(I).Desired.Node_Kind/=Pkg_File_Plan.Regular
              or else (Observed(I).Actual.Node_Kind/=Pkg_File_Plan.Regular
                  and then not (P.Allow_Missing_Files and then Observed(I).Actual.Node_Kind=Pkg_File_Plan.Absent))
            then Blocked:=Blocked+1;
            else
               -- Reserve both new payload and preserved preimage; callers also
               -- budget xattrs/WAL/inodes and filesystem operational headroom.
               if Baseline.Items(I).Desired.Size>P.Maximum_Bytes-Needed then Blocked:=Blocked+1;
               else
                  Needed:=Needed+Baseline.Items(I).Desired.Size;
                  if Observed(I).Actual.Size>P.Maximum_Bytes-Needed then Blocked:=Blocked+1;
                  else Needed:=Needed+Observed(I).Actual.Size; end if;
               end if;
            end if;
         end if;
      end loop;
      if Blocked>0 then Status:=Denied; return; end if;
      if Changed>P.Maximum_Changes then Status:=Exhausted; return; end if;
      if Changed=0 then Status:=OK; return; end if;
      Result.Root_ID:=C.Root_ID; Result.Transaction_ID:=C.Transaction_ID;
      Result.Base_Generation:=C.Generation; Result.Target_Generation:=C.Generation+1;
      Result.Epoch:=C.Epoch; Result.Fence:=C.Fence;
      Result.Package_Set:=Baseline.Package_Set; Result.Effect_Contract:=Baseline.Contract;
      for I in 1..Baseline.Count loop
         pragma Loop_Invariant(Result.Count<=I-1);
         if not Pkg_File_Plan.Equal(Observed(I).Actual,Baseline.Items(I).Desired) then
            Result.Count:=Result.Count+1; Result.Changes(Result.Count).Path:=Baseline.Items(I).Path;
            Result.Changes(Result.Count).Domain:=Pkg_File_Plan.Packaged_Files;
            Result.Changes(Result.Count).Before:=Observed(I).Actual;
            Result.Changes(Result.Count).After:=Baseline.Items(I).Desired;
         end if;
      end loop;
      if not Pkg_File_Plan.Layout_Valid(Result) then Pkg_File_Plan.Clear(Result); Status:=Invalid_Input; return; end if;
      Status:=OK;
   end Build;
end Pkg_Self_Repair;
