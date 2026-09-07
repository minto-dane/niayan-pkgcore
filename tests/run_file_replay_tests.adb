-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Log_Format; with Pkg_File_Replay; use Pkg_File_Replay;
with Pkg_File_Plan; with Test_Support; use Test_Support;
procedure Run_File_Replay_Tests with SPARK_Mode => Off is
   B : constant Binding := (Root_ID => (others => 1), Transaction_ID => (others => 2),
      Plan_Digest => (others => 3), Epoch => 1, Fence => 4, Target_Generation => 2, Changes => 2);
   R1 : constant Digest := (others => 8);
   R2 : constant Digest := (others => 9);
   V : View;
   procedure Step (Kind : Natural; Index : Counter; D : Digest; Expected : Outcome := OK) is
      E : constant MC_Log_Format.Log_Entry := (Sequence => V.Records + 1, Kind => Kind,
         Root_ID => B.Root_ID, Operation_ID => B.Transaction_ID, Epoch => B.Epoch,
         Token => B.Fence, Index => Index, Generation => B.Target_Generation,
         Object => D, Previous => V.Last_Digest, Result => OK);
      Old : constant View := V;
      S : Outcome;
   begin
      Consume (B,E,V,S); Expect (S = Expected,"record outcome");
      if S /= OK then Expect (V = Old,"invalid record leaves state unchanged");
      else Expect (Valid(B,V),"state invariant"); end if;
   end Step;
   procedure Forward_Complete is
   begin
      Step(Prepared,0,B.Plan_Digest);
      Step(Apply_Intent,1,B.Plan_Digest); Step(Apply_Done,1,B.Plan_Digest);
      Step(Apply_Intent,2,B.Plan_Digest); Step(Apply_Done,2,B.Plan_Digest);
      Step(Applied,0,B.Plan_Digest);
   end;
   S : Outcome; E : MC_Log_Format.Log_Entry; Old : View;
begin
   Expect(Valid(B,V),"initial view");
   Step(Apply_Intent,1,B.Plan_Digest,Corrupt);
   Step(Prepared,0,B.Plan_Digest);
   Expect(not Image_Allowed(B,V,2,False,True),"unlogged future change rejected");
   Step(Apply_Done,1,B.Plan_Digest,Corrupt);
   Step(Apply_Intent,1,B.Plan_Digest);
   Step(Apply_Intent,1,B.Plan_Digest); -- existing same-effect intent replay
   Expect(Image_Allowed(B,V,1,True,False),"pending before allowed");
   Expect(Image_Allowed(B,V,1,False,True),"pending after allowed");
   Expect(not Image_Allowed(B,V,1,False,False),"unknown never allowed");
   Step(Apply_Done,1,B.Plan_Digest);
   Expect(not Image_Allowed(B,V,1,True,False),"completed change cannot revert unnoticed");
   Step(Apply_Intent,2,B.Plan_Digest); Step(Apply_Done,2,B.Plan_Digest);
   Step(Applied,0,B.Plan_Digest);
   Step(Commit_Intent,0,R1); Step(Commit_Intent,0,R2,Corrupt);
   Step(Restore_Intent,2,R1,Corrupt);
   Step(Commit_Intent,0,R1); Step(Committed,0,R1);
   Step(Tail_Repaired,0,R1,Corrupt); Step(Committed,0,R1,Corrupt);
   V := (others => <>); Forward_Complete;
   Step(Restore_Intent,2,R1); Step(Restore_Done,2,R1);
   Expect(not Image_Allowed(B,V,2,False,True),"restored suffix cannot remain after");
   Step(Restore_Intent,1,R2,Corrupt);
   Step(Restore_Intent,1,R1); Step(Restore_Done,1,R1);
   Step(Restored,0,R1); Step(Apply_Intent,1,B.Plan_Digest,Corrupt);
   V := (others => <>); Step(Prepared,0,B.Plan_Digest);
   Old := V;
   E := (Sequence=>V.Records+1,Kind=>Apply_Intent,Root_ID=>B.Root_ID,
      Operation_ID=>B.Transaction_ID,Epoch=>B.Epoch,Token=>B.Fence+1,Index=>1,
      Generation=>B.Target_Generation,Object=>B.Plan_Digest,Previous=>V.Last_Digest,Result=>OK);
   Consume(B,E,V,S); Expect(S=Corrupt and then V=Old,"wrong fencing token rejected");
   E.Token:=B.Fence; E.Previous:=R2;
   Consume(B,E,V,S); Expect(S=Corrupt and then V=Old,"broken hash chain rejected");
   Expect(not Pkg_File_Plan.Allowed_Path("var/log/audit"),"audit root excluded");
   Expect(not Pkg_File_Plan.Allowed_Path("var/lib/mission"),"state root excluded");
   Expect(not Pkg_File_Plan.Allowed_Path("etc/mission/keys"),"trust root excluded");
   Expect(not Pkg_File_Plan.Allowed_Path("var/log/audit/log"),"audit child excluded");
   Expect(Pkg_File_Plan.Allowed_Path("usr/bin/tool"),"normal payload allowed");
   Report;
end Run_File_Replay_Tests;
