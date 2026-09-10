-- SPDX-License-Identifier: BSD-3-Clause
with Test_Support; use Test_Support;
with MC_Types; use MC_Types;
with MC_Maintenance; with Pkg_Holds; with Pkg_Acceptance; with Pkg_Incorporation;
with Pkg_Advisory; with Pkg_Provenance; with Pkg_Activation;
with Pkg_Exposure_Policy; with Pkg_Repository_Trust; with Pkg_Rollback_Contract; with Pkg_Maintenance_Bundle;
procedure Run_Enterprise_Pkg_Tests with SPARK_Mode => Off is
   use type pkg_acceptance.Phase;
   use type pkg_activation.Runtime_State;
   use type pkg_advisory.Decision;
   use type pkg_exposure_policy.Status;
   use type pkg_repository_trust.Decision;
   use type pkg_rollback_contract.Decision;
   C : Pkg_Holds.Catalog;
   S : Pkg_Acceptance.State; E : Pkg_Acceptance.Evidence; O : Outcome;
   I : Pkg_Incorporation.Incorporation; Inv : Pkg_Incorporation.Inventory := (others=><>);
   A : Pkg_Advisory.Advisory; P : Pkg_Provenance.Statement; F : Pkg_Activation.Facts;
   XP : Pkg_Exposure_Policy.Policy; XF : Pkg_Exposure_Policy.Facts;
   RM : Pkg_Repository_Trust.Metadata; RA : Pkg_Repository_Trust.Anchor; RC : Pkg_Rollback_Contract.Contract;
   MB : Pkg_Maintenance_Bundle.Bundle; MI : Pkg_Maintenance_Bundle.Inventory := (others=><>);
begin
   C.Repository:=(others=>1); C.Policy:=(others=>2); C.Epoch:=1; C.Count:=1;
   C.Items(1).Scope:=(others=>3); C.Items(1).Hold_ID:=(others=>4); C.Items(1).Policy:=C.Policy;
   C.Items(1).Subject:=(others=>5); C.Items(1).Reason:=(others=>6); C.Items(1).Serial:=1; C.Items(1).Published_At:=100;
   C.Items(1).Kind:=MC_Maintenance.Error_Hold;
   Expect(Pkg_Holds.Valid(C),"hold-catalog-valid");
   Expect(Pkg_Holds.Blocked(C,C.Items(1).Subject,Pkg_Holds.Apply,150),"hold-blocks-known-bad-apply");

   S.Transaction_ID:=(others=>1); S.Plan:=(others=>2); S.Installed_Image:=(others=>3); S.Recovery_Image:=(others=>4);
   S.Revision:=1; S.Applied_At:=100; S.Last_Observed:=100; S.Current:=Pkg_Acceptance.Trial;
   E.Installed_Image:=S.Installed_Image; E.Recovery_Image:=S.Recovery_Image; E.Minimum_Trial_Ms:=30;
   E.Holds_Clear:=True; E.Integrity_OK:=True; E.Configuration_OK:=True; E.Service_OK:=True; E.No_Open_Incidents:=True; E.Recovery_Pinned:=True;
   for N in 1..3 loop E.Expected_Revision:=S.Revision; E.Now:=100+Counter(N)*10; Pkg_Acceptance.Step(S,Pkg_Acceptance.Observe,E,O); Expect(O=OK,"trial-health-sample"); end loop;
   Expect(S.Current=Pkg_Acceptance.Verified,"trial-becomes-verified");
   E.Expected_Revision:=S.Revision; E.Now:=140; E.Acceptance_Authorized:=True;
   Pkg_Acceptance.Step(S,Pkg_Acceptance.Accept_Change,E,O); Expect(O=OK and then S.Current=Pkg_Acceptance.Accepted,"apply-separate-from-accept");
   E.Expected_Revision:=S.Revision; E.Now:=150; E.Commit_Authorized:=True;
   Pkg_Acceptance.Step(S,Pkg_Acceptance.Commit,E,O); Expect(O=OK and then S.Current=Pkg_Acceptance.Committed,"accept-separate-from-commit");

   I.ID:=(others=>1); I.Policy:=(others=>2); I.Repository:=(others=>3); I.Epoch:=1; I.Count:=2;
   I.Items(1):=(Name=>(others=>10),EVR=>(others=>11),Package_Digest=>(others=>12),Required=>True);
   I.Items(2):=(Name=>(others=>20),EVR=>(others=>21),Package_Digest=>(others=>22),Required=>True);
   Inv(1):=(Name=>I.Items(1).Name,EVR=>I.Items(1).EVR,Package_Digest=>I.Items(1).Package_Digest);
   Inv(2):=(Name=>I.Items(2).Name,EVR=>I.Items(2).EVR,Package_Digest=>I.Items(2).Package_Digest);
   Expect(Pkg_Incorporation.Satisfied(I,Inv,2),"incorporation-exact-composition");
   Inv(2).EVR:=(others=>99); Expect(not Pkg_Incorporation.Satisfied(I,Inv,2),"incorporation-rejects-substitution");

   A.ID:=(others=>1); A.Package_ID:=(others=>2); A.Fixed_Build:=(others=>3); A.Metadata:=(others=>4); A.Published_At:=100; A.Security_Epoch:=5;
   A.Level:=Pkg_Advisory.Critical; A.Exploited:=True;
   Expect(Pkg_Advisory.Decide(A,(others=>9),5)=Pkg_Advisory.Emergency_Change,"exploited-critical-expedites");
   A.Known_Bad:=True; Expect(Pkg_Advisory.Decide(A,(others=>9),5)=Pkg_Advisory.Block_Installation,"known-bad-blocked");

   P.Package_ID:=(others=>1); P.Source:=(others=>2); P.Build_Recipe:=(others=>3); P.Builder:=(others=>4); P.Repository:=(others=>5);
   P.Receipt:=(others=>6); P.Repository_Epoch:=10; P.Build_Epoch:=10; P.Assurance:=Pkg_Provenance.Transparency_Bound;
   P.Package_Signature:=True; P.Metadata_Signature:=True; P.Receipt_Verified:=True; P.Builder_Allowed:=True; P.Source_Allowed:=True; P.Recipe_Allowed:=True;
   Expect(Pkg_Provenance.Admissible(P,Pkg_Provenance.Transparency_Bound,10),"provenance-admission");
   P.Builder_Allowed:=False; Expect(not Pkg_Provenance.Admissible(P,Pkg_Provenance.Signed_Binary,10),"unknown-builder-denied");

   F.Installed:=(others=>1); F.Running:=F.Installed; F.Accepted:=(others=>2); F.Required:=Pkg_Advisory.Service_Restart;
   F.Health_OK:=True; F.Configuration_OK:=True; F.Services_Pending:=1;
   Expect(Pkg_Activation.Evaluate(F)=Pkg_Activation.Partially_Active,"running-state-not-confused-with-installed-state");
   F.Services_Pending:=0; Expect(Pkg_Activation.Evaluate(F)=Pkg_Activation.Active,"activation-after-required-restart");

   A.Known_Bad:=False; A.Exploited:=True; XP.Exploited_Max_Ms:=100; XP.Critical_Max_Ms:=1_000;
   XF.Advisory:=A; XF.Now:=250; XF.First_Observed_At:=100; XF.Fixed_Build_Available:=True; XF.Recovery_Pinned:=True;
   Expect(Pkg_Exposure_Policy.Evaluate(XP,XF)=Pkg_Exposure_Policy.Overdue,"exploited-fix-window-is-bounded");

   RM.Repository_ID:=(others=>1); RM.Snapshot:=(others=>2); RM.Root_Keys:=(others=>3); RM.Repository_Epoch:=10; RM.Snapshot_Version:=20; RM.Timestamp_Version:=30;
   RM.Produced_At:=100; RM.Expires_At:=500; RM.Root_Signed:=True; RM.Snapshot_Signed:=True; RM.Timestamp_Signed:=True;
   RA.Repository_ID:=RM.Repository_ID; RA.Root_Keys:=RM.Root_Keys; RA.Minimum_Epoch:=10; RA.Minimum_Snapshot_Version:=20; RA.Minimum_Timestamp_Version:=30; RA.Last_Snapshot:=RM.Snapshot;
   Expect(Pkg_Repository_Trust.Check(RM,RA,200)=Pkg_Repository_Trust.Trusted,"repository-metadata-monotonic");
   RM.Snapshot_Version:=19; Expect(Pkg_Repository_Trust.Check(RM,RA,200)=Pkg_Repository_Trust.Rollback,"repository-rollback-rejected");

   RC.Package_ID:=(others=>1); RC.From_State:=(others=>2); RC.To_State:=(others=>3); RC.Data_Schema_From:=1; RC.Data_Schema_To:=2;
   RC.Data_Migration:=Pkg_Rollback_Contract.Irreversible; RC.Restore_Required_For_Reverse:=True; RC.Restore_Verified:=True;
   Expect(Pkg_Rollback_Contract.Evaluate(RC)=Pkg_Rollback_Contract.Restore_Rollback,"irreversible-data-change-needs-tested-restore");

   MB.ID:=(others=>1); MB.Repository:=(others=>2); MB.Policy:=(others=>3); MB.Baseline:=(others=>4); MB.Epoch:=10; MB.Security_Epoch:=11; MB.Count:=2; MB.Signed:=True; MB.Cumulative:=True;
   MB.Content(1):=(Package_ID=>(others=>10),Required_Build=>(others=>11),Advisory=>(others=>12),Required=>True);
   MB.Content(2):=(Package_ID=>(others=>20),Required_Build=>(others=>21),Advisory=>(others=>22),Required=>True);
   MI(1):=(Package_ID=>MB.Content(1).Package_ID,Build=>MB.Content(1).Required_Build); MI(2):=(Package_ID=>MB.Content(2).Package_ID,Build=>MB.Content(2).Required_Build);
   Expect(Pkg_Maintenance_Bundle.Valid(MB) and then Pkg_Maintenance_Bundle.Satisfied(MB,MI,2),"cumulative-maintenance-bundle-exactly-satisfied");
   MI(2).Build:=(others=>99); Expect(not Pkg_Maintenance_Bundle.Satisfied(MB,MI,2),"maintenance-bundle-missing-build-visible");
   Report;
end Run_Enterprise_Pkg_Tests;
