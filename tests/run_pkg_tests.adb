-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Codec;
with Pkg_Transactions; with Pkg_Journal; with Pkg_Recovery;
with Pkg_Versions; with Pkg_Inventory; with Pkg_Admission;
with Test_Support; use Test_Support;
procedure Run_Pkg_Tests with SPARK_Mode => Off is
   use Pkg_Transactions;
   use type Byte;
   use type Pkg_Journal.Log_Record;
   use type Pkg_Journal.Head;
   use type Pkg_Recovery.Recovery_Action;
   use type Pkg_Inventory.Plan_Status;
   use type Pkg_Versions.Ordering;
   T, Before : Transaction;
   E, Missing : Evidence;
   A : Effect;
   S : Outcome;
   Commands : constant array(Positive range 1..9) of Command :=
     (Validate_Plan,Record_Staged,Record_Quiesced,Begin_Apply,Record_Applied,
      Begin_Check,Record_Verified,Begin_Commit,Record_Committed);
   R, Decoded : Pkg_Journal.Log_Record;
   Head, Saved_Head : Pkg_Journal.Head;
   Raw, Bad : Pkg_Journal.Encoded_Record;
   RE : Pkg_Recovery.Recovery_Evidence;
   Universe : Pkg_Inventory.Model;
   Old_Set, New_Set : Pkg_Inventory.Selection := (others=>False);
   F : Pkg_Admission.Facts;
   procedure Compare (L,R : String; Want : Pkg_Versions.Ordering) is
   begin Expect(Pkg_Versions.Compare(L,R)=Want,"version-" & L & "/" & R); end Compare;
   function Initialized return Transaction is
     (ID=>(others=>1),Plan_Digest=>(others=>2),Base_Generation=>1,
      Membership_Epoch=>1,Fence_Token=>5,Revision=>0,Current=>Empty);
begin
   E := (Expected_Revision=>0,Observed_Generation=>1,Membership_Epoch=>1,Fence_Token=>5,
     Now=>100,Lease_Deadline=>200,Bound_Plan=>(others=>2),others=>True);
   T := Initialized;
   for C of Commands loop
      E.Expected_Revision := T.Revision;
      Step(T,C,E,A,S); Expect(S=OK,"transaction-valid-sequence");
   end loop;
   Expect(T.Current=Committed,"transaction-committed");
   Before := T; E.Expected_Revision := T.Revision;
   Step(T,Begin_Apply,E,A,S); Expect(S/=OK and then T=Before,"terminal-is-terminal");
   for P in Phase loop
      for C in Command loop
         T := Initialized; T.Current := P; T.Revision := 10;
         Missing := (others=><>); Missing.Expected_Revision := 10; Before := T;
         Step(T,C,Missing,A,S);
         if S/=OK then Expect(T=Before and then A=No_Effect,"reject-is-noop"); end if;
         Expect(A not in Apply_Files | Commit_Metadata | Restore_Files,"no-evidence-no-write");
      end loop;
   end loop;
   T := Initialized; T.Current := Quiesced; T.Revision := 3;
   E.Expected_Revision := 3; Missing := E; Missing.Lease_Deadline := Missing.Now;
   Before := T; Step(T,Begin_Apply,Missing,A,S);
   Expect(S/=OK and then T=Before,"expired-lease-no-apply");
   Missing := E; Missing.Fence_Token := 4;
   Step(T,Begin_Apply,Missing,A,S); Expect(S/=OK and then T=Before,"old-fence-no-apply");
   Missing := E; Missing.Intent_Durable := False;
   Step(T,Begin_Apply,Missing,A,S); Expect(S/=OK and then T=Before,"no-durable-intent-no-apply");
   Missing := E; Missing.No_Unknown_Effects := False;
   Step(T,Begin_Apply,Missing,A,S); Expect(S/=OK and then T=Before,"unknown-effect-no-apply");
   T.Revision := Counter'Last; E.Expected_Revision := Counter'Last; Before := T;
   Step(T,Begin_Reconcile,E,A,S); Expect(S=Exhausted and then T=Before,"revision-no-wrap");
   R := (Sequence_Number=>1,Membership_Epoch=>1,Fence_Token=>5,
     Transaction_ID=>(others=>1),Current=>Validated,Plan=>(others=>2),
     Root_ID=>(others=>3),others=><>);
   Raw := Pkg_Journal.Encode(R);
   Pkg_Journal.Decode(Raw,Decoded,S); Expect(S=OK and then Decoded=R,"journal-roundtrip");
   for J in Raw'Range loop
      Bad := Raw; Bad(J) := Bad(J) xor 1;
      Pkg_Journal.Decode(Bad,Decoded,S); Expect(S/=OK,"journal-bitflip");
   end loop;
   for N in 0..255 loop
      Pkg_Journal.Decode(Raw(1..N),Decoded,S); Expect(S/=OK,"journal-truncated");
   end loop;
   Head.Root_ID := R.Root_ID;
   Pkg_Journal.Extend(Head,R,S); Expect(S=OK and then Head.Sequence_Number=1,"journal-chain-start");
   Saved_Head := Head;
   Pkg_Journal.Extend(Head,R,S); Expect(S/=OK and then Head=Saved_Head,"journal-replay-denied");
   R.Sequence_Number := 2; R.Previous := Head.Last_Digest;
   Pkg_Journal.Extend(Head,R,S); Expect(S=OK and then Head.Sequence_Number=2,"journal-chain-next");
   RE := (others=>True);
   Expect(Pkg_Recovery.Decide(Applying,Pkg_Recovery.Mixed_Image,RE)=Pkg_Recovery.Restore_Before,
          "recovery-with-complete-evidence");
   RE.Data_Backward_Compatible := False;
   Expect(Pkg_Recovery.Decide(Applying,Pkg_Recovery.Mixed_Image,RE)=Pkg_Recovery.Quarantine,
          "irreversible-data-no-rollback");
   RE := (others=>True); RE.External_Effects_Known := False;
   Expect(Pkg_Recovery.Decide(Applying,Pkg_Recovery.After_Image,RE)=Pkg_Recovery.Reconcile_External,
          "unknown-external-outcome");
   RE := (others=>True); RE.Trusted_Anchor_Valid := False;
   Expect(Pkg_Recovery.Decide(Committed,Pkg_Recovery.After_Image,RE)=Pkg_Recovery.Quarantine,
          "missing-anchor-no-success");
   Compare("1","1",Pkg_Versions.Equal);
   Compare("1.10","1.9",Pkg_Versions.Newer);
   Compare("1.01","1.1",Pkg_Versions.Equal);
   Compare("1.0~rc1","1.0",Pkg_Versions.Older);
   Compare("1.0^git1","1.0",Pkg_Versions.Newer);
   Compare("1.0^git1","1.0.1",Pkg_Versions.Older);
   Compare("1a","1.1",Pkg_Versions.Older);
   Compare("","",Pkg_Versions.Equal);
   Compare("1+0","1.0",Pkg_Versions.Equal);
   Universe.Base_Generation := 7; Universe.Universe_Digest := (others=>7);
   Universe.Packages(1) := (Available=>True,Admitted=>True,Protected_Package=>True,
                          Allow_Replacement=>False,Artifact=>(others=>1));
   Universe.Packages(2) := (Available=>True,Admitted=>True,Artifact=>(others=>2),others=>False);
   Old_Set(1) := True; New_Set := Old_Set; New_Set(2) := True;
   Universe.Requires_All(2,1) := True;
   Expect(Pkg_Inventory.Check(Universe,Old_Set,New_Set,7,(others=>7))=Pkg_Inventory.Plan_OK,
          "inventory-closure");
   New_Set(1) := False;
   Expect(Pkg_Inventory.Check(Universe,Old_Set,New_Set,7,(others=>7))=Pkg_Inventory.Protected_Removal,
          "protected-removal");
   New_Set := Old_Set;
   Expect(Pkg_Inventory.Check(Universe,Old_Set,New_Set,6,(others=>7))=Pkg_Inventory.Stale_Base,
          "inventory-generation-cas");
   Expect(not Pkg_Admission.Admissible(F),"empty-admission-denied");
   Report;
end Run_Pkg_Tests;
