-- SPDX-License-Identifier: MIT
with Ada.Command_Line; with Ada.Text_IO; with Ada.Unchecked_Deallocation;
with MC_Types; use MC_Types; with MC_Runtime; with MC_File_IO; with MC_SHA256;
with MC_Hex; with MC_Clock; with MC_Numbers;
with Pkg_Inventory; with Pkg_Self_Repair; with Pkg_Scrubber;
procedure Pkg_Scrubctl with SPARK_Mode=>Off is
   use Ada.Command_Line; use Ada.Text_IO;
   type Manifest_Access is access Pkg_Inventory.Manifest;
   type Findings_Access is access Pkg_Self_Repair.Finding_Array;
   procedure Free is new Ada.Unchecked_Deallocation(Pkg_Inventory.Manifest,Manifest_Access);
   procedure Free is new Ada.Unchecked_Deallocation(Pkg_Self_Repair.Finding_Array,Findings_Access);
   M : Manifest_Access:=null; Findings : Findings_Access:=null;
   Expected : Digest; Matched,Different,Unknown : Natural; Now : Counter;
   S : Outcome:=Invalid_Input;
begin
   if Argument_Count/=5 or else Argument(1)/="scan" then
      Put_Line("pkg_scrubctl scan ROOT STATE-DIRECTORY INVENTORY-FILE EXPECTED-SHA256");
      Put_Line("Read-only scoped inventory audit; a caller-supplied digest is not source authentication.");
      Set_Exit_Status(Failure); return;
   end if;
   MC_Runtime.Initialize(S); if S/=OK then Set_Exit_Status(Failure); return; end if;
   MC_Hex.Decode(Argument(5),Expected,S);
   if S/=OK or else Expected=Zero_Digest then Set_Exit_Status(Failure); return; end if;
   M:=new Pkg_Inventory.Manifest; Findings:=new Pkg_Self_Repair.Finding_Array;
   declare Data : constant Bytes:=MC_File_IO.Read_File(Argument(4),Pkg_Inventory.Maximum_Encoding); begin
      if MC_SHA256.Hash(Data)/=Expected then S:=Denied;
      else Pkg_Inventory.Decode(Data,M.all,S); end if;
   end;
   if S=OK then MC_Clock.Boottime_Milliseconds(Now,S); end if;
   if S=OK and then Now>Counter'Last-60_000 then S:=Exhausted; end if;
   if S=OK then
      Pkg_Scrubber.Scan(Argument(2),Argument(3),M.all,256*1_024*1_024,Now+60_000,
         Findings.all,Matched,Different,Unknown,S);
      Put_Line("matched=" & Natural'Image(Matched)); Put_Line("different=" & Natural'Image(Different));
      Put_Line("unknown=" & Natural'Image(Unknown));
      if S=OK and then (Different>0 or else Unknown>0) then S:=Conflict; end if;
   end if;
   Put_Line("scrub-result=" & Outcome'Image(S)); Free(M); Free(Findings);
   if S/=OK then Set_Exit_Status(Failure); end if;
exception when others=>Free(M); Free(Findings); Set_Exit_Status(Failure);
end Pkg_Scrubctl;
