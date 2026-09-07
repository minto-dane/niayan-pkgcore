-- SPDX-License-Identifier: MIT
with Ada.Command_Line;
with MC_Types; use MC_Types;
with MC_Durable; with Pkg_Journal; with Pkg_Journal_IO; with Pkg_Transactions;
with Test_Support; use Test_Support;
procedure Run_Journal_IO_Tests with SPARK_Mode => Off is
   use type Pkg_Journal.Head;
   Directory : MC_Durable.Directory_Handle;
   File : MC_Durable.File_Handle;
   Head, Scanned, Saved : Pkg_Journal.Head;
   Item : Pkg_Journal.Log_Record;
   Status : Outcome;
   Length : Counter;
begin
   Expect(Ada.Command_Line.Argument_Count=1,"private-directory-argument");
   MC_Durable.Open_Private_Directory(Ada.Command_Line.Argument(1),Directory,Status);
   Expect(Status=OK,"open-private-directory");
   MC_Durable.Open_Journal(Directory,"journal.mcl",File,Status);
   Expect(Status=OK,"create-locked-journal");
   Head.Root_ID := (others=>3);
   Pkg_Journal_IO.Scan(File,Head.Root_ID,Scanned,Status);
   Expect(Status=OK and then Scanned.Sequence_Number=0,"empty-journal");
   Item := (Sequence_Number=>1,Membership_Epoch=>1,Fence_Token=>1,
     Transaction_ID=>(others=>1),Plan=>(others=>2),Root_ID=>Head.Root_ID,
     Current=>Pkg_Transactions.Validated,others=><>);
   Pkg_Journal_IO.Append(File,Head,Item,Status); Expect(Status=OK,"durable-record-one");
   Saved := Head;
   Pkg_Journal_IO.Append(File,Head,Item,Status);
   Expect(Status/=OK and then Head=Saved,"invalid-append-no-head-change");
   MC_Durable.Size(File,Length,Status); Expect(Status=OK and then Length=256,"no-extra-write");
   Item.Sequence_Number := 2; Item.Previous := Head.Last_Digest;
   Pkg_Journal_IO.Append(File,Head,Item,Status); Expect(Status=OK,"durable-record-two");
   MC_Durable.Close(File,Status); Expect(Status=OK,"close-writer");
   MC_Durable.Open_Readonly(Directory,"journal.mcl",File,Status); Expect(Status=OK,"open-reader");
   Pkg_Journal_IO.Scan(File,Head.Root_ID,Scanned,Status);
   Expect(Status=OK and then Scanned=Head,"reopen-and-replay");
   Pkg_Journal_IO.Check_Anchor(Scanned,Head,Status); Expect(Status=OK,"exact-anchor");
   Pkg_Journal_IO.Check_Anchor(Scanned,Saved,Status); Expect(Status/=OK,"stale-anchor");
   MC_Durable.Close(File,Status); Expect(Status=OK,"close-reader");
   MC_Durable.Open_Journal(Directory,"journal.mcl",File,Status); Expect(Status=OK,"reopen-writer");
   MC_Durable.Append(File,512,Bytes'(1=>16#FF#),Status); Expect(Status=OK,"inject-private-tail-byte");
   Pkg_Journal_IO.Scan(File,Head.Root_ID,Scanned,Status); Expect(Status=Corrupt,"partial-tail-rejected");
   MC_Durable.Size(File,Length,Status); Expect(Status=OK and then Length=513,"tail-not-silently-truncated");
   MC_Durable.Close(File,Status); Expect(Status=OK,"final-close-file");
   MC_Durable.Close(Directory,Status); Expect(Status=OK,"final-close-directory");
   Report;
end Run_Journal_IO_Tests;
