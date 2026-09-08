-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Codec;
with Pkg_Transactions; with Pkg_Journal; with Pkg_Recovery;
with Pkg_Versions; with Pkg_Admission;
with Resolver_Model; with Resolver_Builder; with Resolver_Verify;
with Resolver_Wire; with MC_SHA256;
with Test_Support; use Test_Support;
procedure Run_Pkg_Tests with SPARK_Mode => Off is
   use Pkg_Transactions;
   use type Byte;
   use type Pkg_Journal.Log_Record;
   use type Pkg_Journal.Head;
   use type Pkg_Recovery.Recovery_Action;
   use type Resolver_Model.Check_Code;
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
   type Universe_Access is access Resolver_Model.Universe;
   Universe : constant Universe_Access := new Resolver_Model.Universe;
   Proposal : Resolver_Model.Proposal;
   Resolution : Resolver_Model.Report;
   Node, Left_Node, Right_Node : Resolver_Model.Node_ID;
   Fuel, Encoded_Size : Natural;
   Universe_Data : Bytes (1 .. 4096);
   Universe_Hash : Digest;
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
   declare
      Empty : constant String(-10 .. -11) := "";
      Shifted : constant String(27 .. 30) := "1.10";
      High : constant String(Integer'Last-3 .. Integer'Last-1) := "1.9";
   begin
      Compare(Empty,"",Pkg_Versions.Equal);
      Compare(Empty,High,Pkg_Versions.Older);
      Compare(Shifted,High,Pkg_Versions.Newer);
      Compare(High,Shifted,Pkg_Versions.Older);
   end;
   -- Dependency selection moved from the old inventory API to resolvercore.
   -- Keep closure, protected-removal and stale-generation coverage here.
   Universe.Subject := (Root => (others => 1), Boot => (others => 2),
      Snapshot => (others => 3), Policy => (others => 4), Adapter_Set => (others => 5),
      Native_Inventory => (others => 6), Configuration => (others => 7),
      Effect_Contracts => (others => 8), Generation => 7);
   Universe.Item_Count := 2; Universe.Maximum_Changes := 2;
   for I in 1 .. 2 loop
      Universe.Items(I) := (Object_Hash => (others => Byte(I)),
         Metadata_Hash => (others => 10), Adapter_Hash => (others => 11),
         Permitted => True, others => <>);
      Resolver_Builder.Presence(Universe.all,I,Node,S); Expect(S=OK,"presence");
   end loop;
   Universe.Items(1).Initially_Present := True;
   Universe.Items(1).Pin := Resolver_Model.Keep_State;
   Resolver_Builder.Negate(Universe.all,2,Left_Node,S); Expect(S=OK,"negate");
   Resolver_Builder.Combine(Universe.all,Resolver_Model.Or_Op,Left_Node,1,Right_Node,S);
   Expect(S=OK,"dependency implication");
   Resolver_Builder.Require(Universe.all,Right_Node,Resolver_Model.Every_Boundary,(others=>12),S);
   Expect(S=OK,"dependency rule");
   Resolver_Wire.Encode(Universe.all,Universe_Data,Encoded_Size,S); Expect(S=OK,"universe encoding");
   Universe_Hash:=MC_SHA256.Hash(Universe_Data(1..Encoded_Size));
   Proposal.Universe_Hash:=Universe_Hash; Proposal.Selected(1..2):=(others=>True);
   Proposal.Count:=1; Proposal.Steps(1):=(Resolver_Model.Add_Item,2);
   Fuel:=Resolver_Verify.Default_Fuel;
   Resolver_Verify.Check_Schedule(Universe.all,Universe_Hash,Proposal,Resolution,Fuel);
   Expect(Resolution.Code=Resolver_Model.Valid_Schedule and then not Resolution.Execution_Permit,"inventory-closure");
   Proposal.Steps(1):=(Resolver_Model.Remove_Item,1);
   Fuel:=Resolver_Verify.Default_Fuel;
   Resolver_Verify.Check_Schedule(Universe.all,Universe_Hash,Proposal,Resolution,Fuel);
   Expect(Resolution.Code=Resolver_Model.Policy_Violation,"protected-removal");
   Universe.Subject.Generation:=8;
   Resolver_Wire.Encode(Universe.all,Universe_Data,Encoded_Size,S); Expect(S=OK,"new generation encoding");
   Universe_Hash:=MC_SHA256.Hash(Universe_Data(1..Encoded_Size));
   Fuel:=Resolver_Verify.Default_Fuel;
   Resolver_Verify.Check_Schedule(Universe.all,Universe_Hash,Proposal,Resolution,Fuel);
   Expect(Resolution.Code=Resolver_Model.Stale_Universe,"inventory-generation-cas");
   Expect(not Pkg_Admission.Admissible(F),"empty-admission-denied");
   Report;
end Run_Pkg_Tests;
