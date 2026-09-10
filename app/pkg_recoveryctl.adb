-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Command_Line; with Ada.Text_IO;
with MC_Types; use MC_Types;
with MC_Hex; with MC_Runtime;
with Pkg_Recovery_Audit; with Pkg_File_Replay;
procedure Pkg_Recoveryctl with SPARK_Mode => Off is
   R : Pkg_Recovery_Audit.Report; S : Outcome;
   Expected : Digest;
begin
   if Ada.Command_Line.Argument_Count /= 4
     or else Ada.Command_Line.Argument (1) /= "inspect" then
      Ada.Text_IO.Put_Line ("usage: pkg_recoveryctl inspect STATE_DIR STORE_DIR PLAN_SHA256");
      Ada.Command_Line.Set_Exit_Status (64); return;
   end if;
   MC_Runtime.Initialize (S);
   if S /= OK then Ada.Text_IO.Put_Line (Outcome'Image(S)); Ada.Command_Line.Set_Exit_Status(78); return; end if;
   MC_Hex.Decode (Ada.Command_Line.Argument(4),Expected,S);
   if S /= OK then Ada.Text_IO.Put_Line ("invalid plan digest"); Ada.Command_Line.Set_Exit_Status(64); return; end if;
   Pkg_Recovery_Audit.Inspect (Ada.Command_Line.Argument(2),Ada.Command_Line.Argument(3),Expected,R,S);
   Ada.Text_IO.Put_Line ("format=mission-recovery-audit-1");
   Ada.Text_IO.Put_Line ("status=" & Outcome'Image(S));
   Ada.Text_IO.Put_Line ("finding=" & Pkg_Recovery_Audit.Finding'Image(R.Result));
   Ada.Text_IO.Put_Line ("phase=" & Pkg_File_Replay.Direction'Image(R.Log_State.Phase));
   Ada.Text_IO.Put_Line ("plan=" & MC_Hex.Encode(R.Plan_Digest));
   Ada.Text_IO.Put_Line ("journal_head=" & MC_Hex.Encode(R.Journal_Head));
   Ada.Text_IO.Put_Line ("records=" & Counter'Image(R.Complete_Records));
   Ada.Text_IO.Put_Line ("bad_record=" & Counter'Image(R.Bad_Record_Number));
   Ada.Text_IO.Put_Line ("tail_bytes=" & Natural'Image(R.Tail_Bytes));
   Ada.Text_IO.Put_Line ("tail_digest=" & MC_Hex.Encode(R.Tail_Digest));
   Ada.Text_IO.Put_Line ("physical_files_checked=false");
   Ada.Text_IO.Put_Line ("recovery_objects_checked=false");
   Ada.Text_IO.Put_Line ("trust_and_quiescence_checked=false");
   Ada.Text_IO.Put_Line ("execution_permit=false");
   if S /= OK then Ada.Command_Line.Set_Exit_Status(2); end if;
exception when others =>
   Ada.Text_IO.Put_Line ("inspection failed; no automatic repair attempted");
   Ada.Command_Line.Set_Exit_Status(2);
end Pkg_Recoveryctl;
