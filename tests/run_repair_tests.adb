-- SPDX-License-Identifier: MIT
with Ada.Unchecked_Deallocation;
with MC_Types; use MC_Types; with MC_SHA256; with MC_Text;
with Pkg_Inventory; with Pkg_Self_Repair; with Pkg_File_Plan; with Pkg_Recovery_Catalog;
with Test_Support; use Test_Support;
procedure Run_Repair_Tests with SPARK_Mode=>Off is
   use type Byte;
   type Manifest_Access is access Pkg_Inventory.Manifest;
   type Findings_Access is access Pkg_Self_Repair.Finding_Array;
   type Plan_Access is access Pkg_File_Plan.Plan;
   procedure Free is new Ada.Unchecked_Deallocation(Pkg_Inventory.Manifest,Manifest_Access);
   procedure Free is new Ada.Unchecked_Deallocation(Pkg_Self_Repair.Finding_Array,Findings_Access);
   procedure Free is new Ada.Unchecked_Deallocation(Pkg_File_Plan.Plan,Plan_Access);
   M,Parsed : Manifest_Access:=new Pkg_Inventory.Manifest;
   Observed : Findings_Access:=new Pkg_Self_Repair.Finding_Array; Plan : Plan_Access:=new Pkg_File_Plan.Plan;
   P : Pkg_Self_Repair.Policy; C : Pkg_Self_Repair.Context;
   Data : Bytes(1..16_384); Used,Changed,Blocked,Selected : Natural; Status : Outcome;
   RP : Pkg_Recovery_Catalog.Policy; Points : Pkg_Recovery_Catalog.Points;
   procedure Build is begin Pkg_Self_Repair.Build(P,C,M.all,Observed.all,Plan.all,Changed,Blocked,Status); end;
begin
   M.Root_ID:=(others=>1); M.Generation:=2; M.Package_Set:=(others=>3); M.Contract:=(others=>4); M.Count:=1;
   MC_Text.Set(M.Items(1).Path,"usr/share/site-app/data",Status); Expect(Status=OK,"inventory-path");
   M.Items(1).Desired:=(Node_Kind=>Pkg_File_Plan.Regular,Mode=>8#644#,UID=>1000,GID=>1000,Size=>3,
      Content=>MC_SHA256.Hash(Bytes'(1,2,3)),Xattrs=>MC_SHA256.Hash(Bytes'(0,0)),others=><>);
   M.Items(1).Allow_Automatic_Repair:=True; M.Items(1).Boot_Or_Security_Critical:=False;
   Pkg_Inventory.Encode(M.all,Data,Used,Status); Expect(Status=OK,"inventory-encode");
   Expect(Pkg_Inventory.Fingerprint(M.all)=MC_SHA256.Hash(Data(1..Used)),"streamed-fingerprint-exact-encoding");
   Pkg_Inventory.Decode(Data(1..Used),Parsed.all,Status); Expect(Status=OK,"inventory-roundtrip-rebased-shape");
   Expect(Pkg_Inventory.Fingerprint(Parsed.all)=Pkg_Inventory.Fingerprint(M.all),"inventory-roundtrip-fingerprint");
   for I in 1..Used loop
      Data(I):=Data(I) xor 1; Pkg_Inventory.Decode(Data(1..Used),Parsed.all,Status);
      Expect(Status/=OK,"inventory-corruption"); Data(I):=Data(I) xor 1;
   end loop;
   P.Root_ID:=M.Root_ID; P.Inventory_Digest:=Pkg_Inventory.Fingerprint(M.all);
   C.Root_ID:=M.Root_ID; C.Inventory_Digest:=P.Inventory_Digest; C.Generation:=2;
   C.Transaction_ID:=(others=>5); C.Boot_ID:=(others=>6); C.Epoch:=1; C.Fence:=1; C.Now:=100;
   C.Stamp:=(C.Boot_ID,1,100,200); C.Authenticated_Baseline:=True; C.Ownership_Exclusive:=True; C.Quiesced:=True;
   C.Capacity_Sufficient:=True; C.Recovery_Artifacts_Verified:=True; C.Intrusion_Suspected:=False;
   C.Hardware_Fault_Suspected:=False; C.Pending_Change:=False; C.Maintenance:=False;
   Observed(1).Known:=True; Observed(1).Actual:=M.Items(1).Desired;
   Build; Expect(Status=OK and then Changed=0 and then Plan.Count=0,"no-drift-no-plan");
   Observed(1).Actual.Content:=MC_SHA256.Hash(Bytes'(4,5,6));
   Build; Expect(Status=OK and then Changed=1 and then Pkg_File_Plan.Layout_Valid(Plan.all),"exact-preimage-repair-proposal");
   Expect(Pkg_File_Plan.Equal(Plan.Changes(1).Before,Observed(1).Actual),"repair-preserves-forensic-preimage");
   C.Intrusion_Suspected:=True; Build; Expect(Status=Denied and then Plan.Count=0,"intrusion-no-overwrite"); C.Intrusion_Suspected:=False;
   C.Hardware_Fault_Suspected:=True; Build; Expect(Status=Denied,"hardware-damage-no-repair-loop"); C.Hardware_Fault_Suspected:=False;
   C.Quiesced:=False; Build; Expect(Status=Denied,"quiescence-required"); C.Quiesced:=True;
   C.Capacity_Sufficient:=False; Build; Expect(Status=Denied,"space-pressure-no-log-deletion"); C.Capacity_Sufficient:=True;
   Observed(1).Known:=False; Build; Expect(Status=Denied and then Blocked=1,"unknown-image-blocks-batch"); Observed(1).Known:=True;
   Observed(1).Actual:=(others=><>); Build; Expect(Status=Denied,"missing-file-default-not-authorized");
   P.Allow_Missing_Files:=True; Build; Expect(Status=OK and then Changed=1,"explicit-missing-file-profile");
   C.Inventory_Digest:=(others=>9); Build; Expect(Status=Denied,"inventory-scope-bound"); C.Inventory_Digest:=P.Inventory_Digest;
   M.Items(1).Desired.UID:=0; Build; Expect(Status=Denied,"changed-normalized-metadata-breaks-fingerprint"); M.Items(1).Desired.UID:=1000;
   Expect(not Pkg_Inventory.Automatic_Path("etc/ssh/sshd_config"),"configuration-never-auto-replaced");
   Expect(not Pkg_Inventory.Automatic_Path("usr/lib/modules/6/kernel.ko"),"kernel-modules-not-autorepaired");
   Expect(not Pkg_Inventory.Automatic_Path("var/lib/database/data"),"business-data-excluded");
   RP.Root_ID:=(others=>1); RP.Now:=200_000; RP.Maximum_Test_Age:=200_000; RP.Current_Data_Schema:=3; RP.Oldest_Trust_Epoch:=2;
   for I in 1..3 loop
      Points(I):=(ID=>(others=>Byte(I)),Root_ID=>RP.Root_ID,Manifest=>(others=>4),Package_Set=>(others=>5),
        Generation=>Counter(I),Trust_Epoch=>2,Data_Schema=>3,Created_At=>1,Verified_At=>100_000,
        Authenticated=>True,Artifacts_Present=>True,Integrity_Checked=>True,Restoration_Tested=>True,
        Signing_Key_Revoked=>False,Vulnerable_Disallowed=>False,Active=>False,Last_Accepted=>False,
        Unresolved_Intent=>False,Pinned_By_Operator=>False,others=><>);
   end loop;
   Pkg_Recovery_Catalog.Select_Point(RP,Points,3,Selected,Status); Expect(Status=OK and then Selected=3,"newest-admissible-recovery");
   Expect(Pkg_Recovery_Catalog.May_Prune(RP,Points,3,1),"retain-two-qualified-points");
   Points(1).Unresolved_Intent:=True; Expect(not Pkg_Recovery_Catalog.May_Prune(RP,Points,3,1),"never-prune-unresolved-intent");
   Points(3).Signing_Key_Revoked:=True; Pkg_Recovery_Catalog.Select_Point(RP,Points,3,Selected,Status);
   Expect(Status=OK and then Selected=2,"revoked-point-not-revived-by-rollback");
   Points(2).Data_Schema:=2; Pkg_Recovery_Catalog.Select_Point(RP,Points,3,Selected,Status);
   Expect(Status/=OK,"software-rollback-not-data-downgrade");
   Free(M); Free(Parsed); Free(Observed); Free(Plan); Report;
exception when others=>Free(M); Free(Parsed); Free(Observed); Free(Plan); raise;
end Run_Repair_Tests;
